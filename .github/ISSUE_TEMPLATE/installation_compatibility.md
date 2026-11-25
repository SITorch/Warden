---
name: Installation or compatibility issue
about: Report a build, install, load, or kernel-compatibility problem
title: ''
labels: installation, compatibility
assignees: ''
---

## Summary

What failed, and at which stage?

## Environment

- WARDEN version / commit:
- Distribution and version:
- Kernel release (`uname -r`) and architecture:
- BTF present (`/sys/kernel/btf/vmlinux` readable?):
- `bpf` in boot `lsm=` list?:
- cgroup v2 mounted?:
- clang / bpftool / Rust versions:
- Privileges used (unprivileged, root, capabilities):

## Stage

- [ ] Build
- [ ] Configuration validation
- [ ] Read-only self-test
- [ ] Service install
- [ ] BPF verification / load
- [ ] Attachment
- [ ] Event observation
- [ ] Enforcement behaviour
- [ ] Uninstall / rollback

## Exact command and result

```text
command:
exit status:
observed output:
```

Use `PASS`, `FAIL`, `SKIP`, `BLOCKED`, `UNKNOWN`, `NOT_RUN`, or `NOT_APPLICABLE`
for each reported check. A skipped privileged test is not a pass.

## Redaction checklist

- [ ] No credentials, tokens, heartbeat URLs (`mac=`), or keys
- [ ] No customer data or guarded-file contents
- [ ] No private hostnames, private IPs, usernames, or absolute home paths
- [ ] No unredacted internal URLs or tenant identifiers

> Do not report a suspected vulnerability here. Use the repository's private
> vulnerability reporting channel once the maintainer confirms it exists and is
> monitored; see `SECURITY.md`.
