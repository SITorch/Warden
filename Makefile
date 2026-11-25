# Warden — build + install.
#
# Two stages:
#   1. clang compiles the CO-RE eBPF object (bpf/warden.bpf.o) against a
#      vmlinux.h generated from THIS host's BTF. That object is embedded into
#      the Rust binary at build time (include_bytes_aligned! in src/loader.rs).
#   2. cargo builds the single userspace agent (dynamically linked to the host's
#      libssl/libcrypto for the optional mTLS bridge; not a fully static binary).
#
# `make` builds both; `make install` places the binary, config, and systemd
# unit; `make check` validates config + toolchain without touching the kernel.

BPF_DIR      := bpf
BPF_SRC      := $(BPF_DIR)/warden.bpf.c
BPF_OBJ      := $(BPF_DIR)/warden.bpf.o
VMLINUX      := $(BPF_DIR)/vmlinux.h

CLANG        ?= clang
BPFTOOL      ?= bpftool
CARGO        ?= cargo
ARCH         := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/armv7l/arm/')

PREFIX       ?= /usr/local
SBINDIR      := $(PREFIX)/sbin
CONFDIR      := /etc/warden
UNITDIR      := /etc/systemd/system
# W-R8: the installed unit's Documentation= directive points here, so this is
# part of the install, not an optional extra.
DOCDIR       := $(PREFIX)/share/doc/warden

# PRQ-01: -fdebug-prefix-map keeps absolute build paths (developer home dirs)
# out of DWARF and BTF line info. The object is otherwise byte-for-byte the
# eBPF program and BTF type data that M15/M16 validated; only debug path
# strings are relativised, so a public checkout cannot leak a builder's path.
CLANG_FLAGS  := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
                -I$(BPF_DIR) -Wall -Wno-unused-function \
                -fdebug-prefix-map='$(CURDIR)=.'

BIN          := target/release/warden

.PHONY: all bpf agent vmlinux check clean install uninstall fmt test test-privileged config-check install-wizard self-test test-cli

all: agent

# ── eBPF object ─────────────────────────────────────────────────────────────
# The committed object is trusted ONLY when bpf/.built-from records the hash of
# every compile input and of the object on disk. Mtime cannot be used: git stamps a
# fresh clone's files with the checkout time, so a file rule can judge the
# shipped .o newer than a just-changed .c and skip the rebuild — which is how a
# pre-fix object once reached the VM (guarded binary SIGSEGV on exec, and the
# host had no clang, so the compile was never even attempted). Hash comparison
# makes that failure loud: stale + no toolchain is an error, never a silent
# skip. (Build on a machine with clang, commit the sources + .o + stamp together.)
#
# Every input, not just warden.bpf.c: the object also comes out of bpf/warden.h (the
# ABI the Rust side mirrors) and bpf/vmlinux.h (the CO-RE layout). A stamp keyed on
# the .c alone printed "bpf object is current" through four edits to warden.h and
# shipped a stale .o (§38, F-38.2) — the same class of bug this rule exists to make
# loud, just on the input side instead of the output side.
BPF_HDR      := $(BPF_DIR)/warden.h
BPF_STAMP    := $(BPF_DIR)/.built-from
# The Rust file that embeds the object. `include_bytes_aligned!` is a COMPILE-TIME
# read, and cargo decides to recompile on mtime: a `.o` replaced by `cp -p`, a
# restored backup or a checkout of an older committed object is older than the last
# build, so cargo keeps the previous binary and every ELF test passes against bytes
# that are no longer on disk (measured: a 25-program object stamped four hours back
# produced a green `cargo test`). Touching the embedder on a real rebuild makes the
# stale case impossible on the `make` path; `tests/embedded_object_is_the_shipped_object.rs`
# catches it on every other path.
BPF_EMBEDDER := src/loader.rs
.PHONY: bpf
bpf:
	@src=$$( { sha256sum $(BPF_SRC) $(BPF_HDR); [ -f $(VMLINUX) ] && sha256sum $(VMLINUX); } | sha256sum | cut -d' ' -f1 ); \
	obj=$$(sha256sum $(BPF_OBJ) 2>/dev/null | cut -d' ' -f1); \
	want=$$src; [ -n "$$obj" ] && want="$$src $$obj"; \
	if [ -f $(BPF_STAMP) ] && [ "$$(cat $(BPF_STAMP))" = "$$want" ]; then \
	    echo "bpf object is current (all compile inputs + object hashes match $(BPF_STAMP))"; \
	elif command -v $(CLANG) >/dev/null 2>&1; then \
	    $(CLANG) $(CLANG_FLAGS) -c $(BPF_SRC) -o $(BPF_OBJ) || exit 1; \
	    printf '%s %s\n' "$$src" "$$(sha256sum $(BPF_OBJ) | cut -d' ' -f1)" > $(BPF_STAMP); \
	    touch $(BPF_EMBEDDER); \
	    echo "built $(BPF_OBJ), re-anchored $(BPF_EMBEDDER) and recorded $(BPF_STAMP)"; \
	else \
	    echo "error: $(BPF_OBJ) does not match $(BPF_SRC) + $(BPF_HDR) and $(CLANG) is not installed." >&2; \
	    echo "  build it where clang exists, then commit the sources + .o + $(BPF_STAMP)." >&2; \
	    exit 1; \
	fi

# Regenerate vmlinux.h from the running kernel's BTF. Only needed when moving to
# a host whose kernel structs differ AND you're not relying on CO-RE relocation
# (normally you are — one object is portable). Kept as an explicit target.
vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)
	@echo "regenerated $(VMLINUX)"

# ── userspace agent (embeds the object above) ───────────────────────────────
agent: bpf
	$(CARGO) build --release --locked

# ── validate without kernel privileges ──────────────────────────────────────
check: agent
	$(BIN) --check --config config/warden.toml

# M16: dedicated configuration-engine operations. `config-check` is safe to run
# from a checkout; `install-wizard` defaults to a read-only preview and requires
# an explicit --yes or --unattended to change anything.
config-check: agent
	$(BIN) --config-validate --strict --config config/warden.toml

install-wizard: agent
	bash scripts/install_wizard.sh --profile $(or $(PROFILE),balanced) --binary $(abspath $(BIN))

self-test: agent
	$(BIN) --self-test --config config/warden.toml

test-cli: agent
	bash scripts/tests/test_config_engine_cli.sh $(abspath $(BIN))
	bash scripts/tests/test_install_wizard.sh $(abspath $(BIN))

test: bpf
	$(CARGO) test --locked

# Privileged integration test. The BPF-LSM runtime case is #[ignore]d so a
# default `cargo test` can never count an unexecuted kernel qualification as
# `ok`. This target delegates to scripts/test-privileged.sh, which checks the
# preconditions and reports an explicit SKIP (exit 77) when they are absent —
# CI cannot grant these capabilities. Run this ONLY in a disposable VM with
# console recovery; never on a production or primary development host.
# Exit convention: 0=PASS, 1=FAIL, 77=SKIP (SKIP is never a PASS).
test-privileged: bpf
	bash scripts/test-privileged.sh

fmt:
	$(CARGO) fmt

# ── install / uninstall ─────────────────────────────────────────────────────
# NB: build as your normal user (`make`), install as root (`sudo make install`).
# install does NOT rebuild — it copies the already-built binary. This keeps the
# cargo/clang toolchain (which lives in your user's ~/.cargo, not on root's PATH)
# out of the sudo step, and keeps target/ owned by you rather than root.
install:
	@test -x "$(BIN)" || { \
		echo "error: $(BIN) not found."; \
		echo "  build it first as your normal user (NOT with sudo):"; \
		echo "      make"; \
		echo "  then re-run:"; \
		echo "      sudo make install"; \
		exit 1; \
	}
	install -d $(SBINDIR) $(CONFDIR) $(DOCDIR)
	install -m 0755 $(BIN) $(SBINDIR)/warden
	@if [ -f $(CONFDIR)/warden.toml ]; then \
		echo "keeping existing $(CONFDIR)/warden.toml (new sample at $(CONFDIR)/warden.toml.sample)"; \
		install -m 0640 config/warden.toml $(CONFDIR)/warden.toml.sample; \
	else \
		install -m 0640 config/warden.toml $(CONFDIR)/warden.toml; \
	fi
	install -m 0644 systemd/warden.service $(UNITDIR)/warden.service
	install -m 0644 systemd/warden-deadman@.service $(UNITDIR)/warden-deadman@.service
	install -m 0644 README.md $(DOCDIR)/README.md
	@# These two files are compiled into tests/network_coverage_matrix.rs; the
	@# standalone archive must ship them or its structural contract will not build.
	install -d $(DOCDIR)/security
	install -m 0644 docs/security/warden_coverage_matrix.md \
		$(DOCDIR)/security/warden_coverage_matrix.md
	install -m 0644 docs/security/warden_phase7_egress_enforcement.md \
		$(DOCDIR)/security/warden_phase7_egress_enforcement.md
	@echo
	@echo "installed. next:"
	@echo "  systemctl daemon-reload"
	@echo "  \$$EDITOR $(CONFDIR)/warden.toml     # set protect/app/bridge for this host"
	@echo "  systemctl enable --now warden"

uninstall:
	-systemctl disable --now warden 2>/dev/null || true
	rm -f $(SBINDIR)/warden $(UNITDIR)/warden.service $(UNITDIR)/warden-deadman@.service
	@# W-R8: remove the installed docs too, so an upgrade+uninstall of a newer
	@# build cannot leave a guide describing a binary that is no longer here.
	rm -f $(DOCDIR)/README.md \
		$(DOCDIR)/security/warden_coverage_matrix.md \
		$(DOCDIR)/security/warden_phase7_egress_enforcement.md
	-rmdir $(DOCDIR)/security 2>/dev/null || true
	-rmdir $(DOCDIR) 2>/dev/null || true
	@echo "removed binary, unit and docs. left $(CONFDIR) in place (contains your policy)."

clean:
	$(CARGO) clean
	rm -f $(BPF_OBJ) $(BPF_STAMP)
