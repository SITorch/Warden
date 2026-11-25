//! btf_compat.rs — a small, dependency-free reader for the target kernel's raw
//! BTF, used to check the six `fexit` prototypes before Warden asks aya to
//! attach them.
//!
//! This is not a second BTF implementation. aya already parses BTF to relocate
//! CO-RE fields, but its parsed type iterators are crate-private, so the loader
//! cannot ask the question this module exists to answer: *does this kernel
//! still expose `udp_recvmsg(struct sock *, struct msghdr *, size_t, int, int *)`?*
//! An fexit program whose parameter list disagrees with the target is not a
//! quiet miscount — the verifier rejects the load, the hook is missing, and the
//! coverage line reports a gap whose cause nobody can see. Checking first lets
//! the loader skip that hook with an explicit reason instead of a generic
//! attach error.
//!
//! Only the facts needed for that decision are read:
//! * `FUNC` type names, whose `type` word points at the prototype;
//! * `FUNC_PROTO` argument count and each argument's resolved kind;
//! * the pointee name of pointer arguments (`sock`, `msghdr`, `int`).
//!
//! Everything else in `/sys/kernel/btf/vmlinux` is skipped by its documented
//! `vlen`/kind shape. The file is world-readable; this module takes no privilege
//! and loads no program. An unreadable file is `UNKNOWN`, never "compatible".

use crate::net_vol::VolumeHook;

/// The kernel's raw BTF. World-readable on a CONFIG_DEBUG_INFO_BTF kernel.
pub const BTF_PATH: &str = "/sys/kernel/btf/vmlinux";

/// `BTF_MAGIC` from `include/uapi/linux/btf.h`, in wire (little-endian) order.
/// The bytes on disk are `9f eb`; transposing them to 0xebf9 makes every real
/// kernel BTF look malformed, which is why the live doctor check caught it.
const BTF_MAGIC: u16 = 0xeb9f;

const KIND_UNKNOWN: u32 = 0;
const KIND_INT: u32 = 1;
const KIND_PTR: u32 = 2;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_FWD: u32 = 7;
const KIND_TYPEDEF: u32 = 8;
const KIND_VOLATILE: u32 = 9;
const KIND_CONST: u32 = 10;
const KIND_RESTRICT: u32 = 11;
const KIND_FUNC: u32 = 12;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_FLOAT: u32 = 16;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_ENUM64: u32 = 19;
const KIND_DECL_TAG: u32 = 17;
const KIND_TYPE_TAG: u32 = 18;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compatibility {
    /// The kernel's FUNC prototype matches this build's fexit parameter list.
    Compatible,
    /// The function or its expected prototype is not this kernel's shape.
    /// The loader skips this hook deliberately and says why.
    Incompatible,
    /// The BTF could not be read or parsed; nothing is concluded.
    Unknown,
}

impl Compatibility {
    pub fn word(self) -> &'static str {
        match self {
            Compatibility::Compatible => "COMPATIBLE",
            Compatibility::Incompatible => "INCOMPATIBLE",
            Compatibility::Unknown => "UNKNOWN",
        }
    }

    pub fn blocks_attach(self) -> bool {
        self == Compatibility::Incompatible
    }
}

#[derive(Debug, Clone)]
pub struct HookCompatibility {
    pub hook: VolumeHook,
    pub status: Compatibility,
    pub detail: String,
}

impl HookCompatibility {
    pub fn reason(&self) -> &str {
        &self.detail
    }
}

#[derive(Debug, Clone)]
struct TypeRecord {
    name_off: u32,
    kind: u32,
    vlen: u32,
    /// The third word of `struct btf_type`: a target/prototype type id for
    /// PTR/FUNC/FUNC_PROTO, a byte size for INT, linkage for VAR.
    data: u32,
    /// Bytes after the 12-byte base type (params, members, array bounds, …).
    extra: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ObservedArg {
    kind: u32,
    type_name: String,
    pointee: Option<String>,
    size_bytes: u32,
}

impl ObservedArg {
    fn describe(&self) -> String {
        match self.kind {
            KIND_PTR => format!("{} *", self.pointee.as_deref().unwrap_or("<unknown>")),
            KIND_INT => format!("{} ({}B)", self.type_name, self.size_bytes),
            other => format!("kind {other} ({})", self.type_name),
        }
    }
}

#[derive(Debug, Clone)]
struct ObservedSignature {
    proto_id: u32,
    args: Vec<ObservedArg>,
}

/// Extract the type ids from a `FUNC_PROTO` parameter area.
///
/// Each parameter is a `struct btf_param { name_off, type }`, so the type id is
/// the second u32 at bytes 4..8 of an 8-byte chunk. `slice::as_chunks::<8>()`
/// is the stable replacement for `chunks_exact(8)`; it has the same full-chunk
/// semantics and leaves any trailing partial bytes untouched, which the caller
/// still detects through the declared-vs-observed argument count check.
fn prototype_param_type_ids(extra: &[u8], vlen: usize) -> Vec<u32> {
    let (chunks, _remainder) = extra.as_chunks::<8>();
    chunks
        .iter()
        .take(vlen)
        .map(|param| u32::from_le_bytes([param[4], param[5], param[6], param[7]]))
        .collect()
}

#[derive(Debug)]
pub struct BtfReadError(pub String);

impl std::fmt::Display for BtfReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub struct RawBtf {
    types: Vec<TypeRecord>,
    strings: Vec<u8>,
}

impl RawBtf {
    pub fn parse(bytes: &[u8]) -> Result<Self, BtfReadError> {
        let u16_at = |at: usize| -> Result<u16, BtfReadError> {
            let b = bytes
                .get(at..at + 2)
                .ok_or_else(|| BtfReadError("BTF header is truncated".to_string()))?;
            Ok(u16::from_le_bytes([b[0], b[1]]))
        };
        let u32_at = |at: usize| -> Result<u32, BtfReadError> {
            let b = bytes
                .get(at..at + 4)
                .ok_or_else(|| BtfReadError("BTF header/type is truncated".to_string()))?;
            Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };

        if u16_at(0)? != BTF_MAGIC {
            return Err(BtfReadError("BTF magic is not 0xeb9f".to_string()));
        }
        let header_len = u32_at(4)? as usize;
        let type_off = u32_at(8)? as usize;
        let type_len = u32_at(12)? as usize;
        let str_off = u32_at(16)? as usize;
        let str_len = u32_at(20)? as usize;
        if header_len < 24 || header_len > bytes.len() {
            return Err(BtfReadError(format!(
                "BTF header length {header_len} is outside the {}-byte file",
                bytes.len()
            )));
        }
        let type_start = header_len
            .checked_add(type_off)
            .ok_or_else(|| BtfReadError("BTF type offset overflow".to_string()))?;
        let type_end = type_start
            .checked_add(type_len)
            .ok_or_else(|| BtfReadError("BTF type length overflow".to_string()))?;
        let str_start = header_len
            .checked_add(str_off)
            .ok_or_else(|| BtfReadError("BTF string offset overflow".to_string()))?;
        let str_end = str_start
            .checked_add(str_len)
            .ok_or_else(|| BtfReadError("BTF string length overflow".to_string()))?;
        if type_end > bytes.len() || str_end > bytes.len() {
            return Err(BtfReadError(
                "BTF type/string section extends past the file".to_string(),
            ));
        }

        let mut types = Vec::new();
        let mut at = type_start;
        while at < type_end {
            if at + 12 > type_end {
                return Err(BtfReadError(
                    "a BTF type's 12-byte base is truncated".to_string(),
                ));
            }
            let name_off = u32_at(at)?;
            let info = u32_at(at + 4)?;
            let data = u32_at(at + 8)?;
            let kind = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;
            // Every kind's trailing bytes have the sizes in include/linux/btf.h.
            // A wrong skip would desynchronise every later type id and turn a
            // real prototype mismatch into a nonsensical one, so the arithmetic
            // is explicit here rather than folded into a table of magic numbers.
            let extra_len = match kind {
                KIND_ARRAY => 12,
                KIND_STRUCT | KIND_UNION => 12 * vlen,
                KIND_ENUM => 8 * vlen,
                KIND_FUNC_PROTO => 8 * vlen,
                // `struct btf_var_secinfo` is {type, offset, size}: three u32s,
                // not the two-word `btf_param`. Counting it as 8 bytes was the
                // first desynchroniser on the target's real vmlinux BTF.
                KIND_DATASEC => 12 * vlen,
                KIND_VAR | KIND_DECL_TAG => 4,
                // `struct btf_type` is already the whole TYPE_TAG record; it
                // has no `component_index` the way DECL_TAG does. Giving it 4
                // bytes desynchronised every later type id.
                KIND_TYPE_TAG => 0,
                // `struct btf_enum64` is three u32s (12 bytes), not four; the
                // 64-bit value is split across `val_lo32`/`val_hi32` inside
                // that record. Counting 16 desynchronised a later STRUCT on
                // the host's newer kernel.
                KIND_ENUM64 => 12 * vlen,
                // INT, PTR, typedef/qualifiers, FUNC and FLOAT carry everything
                // they need in the 12-byte base plus `vlen`/`data`.
                // INT is the one base-only kind with a trailing word: the
                // encoding/bit-layout u32 after `size`. Forgetting it shifts
                // every type after the first integer in a real vmlinux BTF.
                KIND_INT => 4,
                KIND_UNKNOWN | KIND_PTR | KIND_FWD | KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST
                | KIND_RESTRICT | KIND_FUNC | KIND_FLOAT => 0,
                other => {
                    return Err(BtfReadError(format!(
                        "unsupported BTF kind {other}; refusing to guess its size"
                    )))
                }
            };
            let extra_end = at + 12 + extra_len;
            if extra_end > type_end {
                return Err(BtfReadError(format!(
                    "BTF type {}{} trailing bytes run past the type section",
                    kind, vlen
                )));
            }
            types.push(TypeRecord {
                name_off,
                kind,
                vlen: vlen as u32,
                data,
                extra: bytes[at + 12..extra_end].to_vec(),
            });
            at = extra_end;
        }
        Ok(Self {
            types,
            strings: bytes[str_start..str_end].to_vec(),
        })
    }

    fn type_by_id(&self, id: u32) -> Result<&TypeRecord, BtfReadError> {
        if id == 0 || id as usize > self.types.len() {
            return Err(BtfReadError(format!(
                "BTF type id {id} is outside the {} types parsed",
                self.types.len()
            )));
        }
        Ok(&self.types[id as usize - 1])
    }

    fn string_at(&self, offset: u32) -> Result<&str, BtfReadError> {
        let offset = offset as usize;
        let rest = self
            .strings
            .get(offset..)
            .ok_or_else(|| BtfReadError(format!("BTF string offset {offset} is out of range")))?;
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        std::str::from_utf8(&rest[..end])
            .map_err(|e| BtfReadError(format!("BTF string is not UTF-8: {e}")))
    }

    /// Resolve typedef/const/volatile/restrict wrappers to the underlying type.
    /// The fexit parameter's pointee is `struct sock`, for example, whether the
    /// prototype spells it `sock`, `const sock`, or a typedef to either.
    fn resolve_id(&self, mut id: u32) -> Result<u32, BtfReadError> {
        for _ in 0..32 {
            let ty = self.type_by_id(id)?;
            if matches!(
                ty.kind,
                KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT
            ) {
                id = ty.data;
                continue;
            }
            return Ok(id);
        }
        Err(BtfReadError("BTF qualifier chain is cyclic".to_string()))
    }

    fn observed_arg(&self, id: u32) -> Result<ObservedArg, BtfReadError> {
        let id = self.resolve_id(id)?;
        let ty = self.type_by_id(id)?;
        let type_name = self.string_at(ty.name_off)?.to_string();
        let pointee = if ty.kind == KIND_PTR {
            let target_id = self.resolve_id(ty.data)?;
            let target = self.type_by_id(target_id)?;
            Some(self.string_at(target.name_off)?.to_string())
        } else {
            None
        };
        Ok(ObservedArg {
            kind: ty.kind,
            type_name,
            pointee,
            size_bytes: if ty.kind == KIND_INT { ty.data } else { 0 },
        })
    }

    fn signature(&self, func: &str) -> Result<ObservedSignature, BtfReadError> {
        let func_type = self
            .types
            .iter()
            .find(|ty| ty.kind == KIND_FUNC && self.string_at(ty.name_off).is_ok_and(|n| n == func))
            .ok_or_else(|| BtfReadError(format!("kernel BTF has no FUNC type named {func}")))?;
        let proto_id = func_type.data;
        let proto = self.type_by_id(proto_id)?;
        if proto.kind != KIND_FUNC_PROTO {
            return Err(BtfReadError(format!(
                "FUNC {func} points at type {proto_id}, which is kind {} not FUNC_PROTO",
                proto.kind
            )));
        }
        let param_type_ids = prototype_param_type_ids(&proto.extra, proto.vlen as usize);
        let mut args = Vec::with_capacity(param_type_ids.len());
        for type_id in param_type_ids {
            args.push(self.observed_arg(type_id)?);
        }
        if args.len() != proto.vlen as usize {
            return Err(BtfReadError(format!(
                "FUNC_PROTO {proto_id} declares {} params but has {} bytes of params",
                proto.vlen,
                proto.extra.len()
            )));
        }
        Ok(ObservedSignature { proto_id, args })
    }
}

#[derive(Debug, Clone, Copy)]
enum ExpectedArg {
    /// A pointer whose resolved pointee type has this BTF name.
    PointerTo(&'static str),
    /// An integer at least this many bytes wide (`size_t`/`size` vs `int`).
    IntegerAtLeast(u32),
}

fn expected_args(hook: VolumeHook) -> &'static [ExpectedArg] {
    match hook {
        VolumeHook::TcpSendMsg | VolumeHook::UdpSendMsg | VolumeHook::Udp6SendMsg => &[
            ExpectedArg::PointerTo("sock"),
            ExpectedArg::PointerTo("msghdr"),
            ExpectedArg::IntegerAtLeast(8), // size_t size / size_t len
        ],
        VolumeHook::TcpCleanupRbuf => &[
            ExpectedArg::PointerTo("sock"),
            ExpectedArg::IntegerAtLeast(4), // int copied
        ],
        VolumeHook::UdpRecvMsg | VolumeHook::Udp6RecvMsg => &[
            ExpectedArg::PointerTo("sock"),
            ExpectedArg::PointerTo("msghdr"),
            ExpectedArg::IntegerAtLeast(8), // size_t len
            ExpectedArg::IntegerAtLeast(4), // int flags
            ExpectedArg::PointerTo("int"),  // int *addr_len
        ],
    }
}

fn compare(hook: VolumeHook, sig: &ObservedSignature) -> HookCompatibility {
    let expected = expected_args(hook);
    let observed = &sig.args;
    if observed.len() != expected.len() {
        return HookCompatibility {
            hook,
            status: Compatibility::Incompatible,
            detail: format!(
                "{} declares {} arguments, this build's fexit needs {} for BTF proto {} ({})",
                hook.func(),
                observed.len(),
                expected.len(),
                sig.proto_id,
                observed
                    .iter()
                    .map(ObservedArg::describe)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
    }
    for (i, (want, got)) in expected.iter().zip(observed.iter()).enumerate() {
        let ok = match want {
            ExpectedArg::PointerTo(name) => {
                got.kind == KIND_PTR && got.pointee.as_deref() == Some(*name)
            }
            ExpectedArg::IntegerAtLeast(size) => got.kind == KIND_INT && got.size_bytes >= *size,
        };
        if !ok {
            return HookCompatibility {
                hook,
                status: Compatibility::Incompatible,
                detail: format!(
                    "{} argument {} is {}, which is not {want:?}; BTF proto {}",
                    hook.func(),
                    i,
                    got.describe(),
                    sig.proto_id
                ),
            };
        }
    }
    HookCompatibility {
        hook,
        status: Compatibility::Compatible,
        detail: format!(
            "BTF proto {} matches {} arguments ({})",
            sig.proto_id,
            observed.len(),
            observed
                .iter()
                .map(ObservedArg::describe)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Check one hook against an already-parsed raw BTF image.
pub fn check_against(btf: &RawBtf, hook: VolumeHook) -> HookCompatibility {
    match btf.signature(hook.func()) {
        Ok(sig) => compare(hook, &sig),
        Err(e) => HookCompatibility {
            hook,
            status: Compatibility::Incompatible,
            detail: e.to_string(),
        },
    }
}

/// Read the target kernel's raw BTF and check all six hooks in `VolumeHook::ALL`
/// order. A read/parse failure marks every hook UNKNOWN: the loader must not
/// skip an attach because the file was momentarily unreadable, but doctor and
/// the journal must say that no compatibility conclusion was reached.
pub fn check_all(path: &str) -> Vec<HookCompatibility> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            let reason = format!("cannot read {path}: {e}");
            return VolumeHook::ALL
                .iter()
                .map(|&hook| HookCompatibility {
                    hook,
                    status: Compatibility::Unknown,
                    detail: reason.clone(),
                })
                .collect();
        }
    };
    let btf = match RawBtf::parse(&bytes) {
        Ok(b) => b,
        Err(e) => {
            let reason = format!("cannot parse {path}: {e}");
            return VolumeHook::ALL
                .iter()
                .map(|&hook| HookCompatibility {
                    hook,
                    status: Compatibility::Unknown,
                    detail: reason.clone(),
                })
                .collect();
        }
    };
    VolumeHook::ALL
        .iter()
        .map(|&hook| check_against(&btf, hook))
        .collect()
}

/// Operator-facing one-line summary for `--doctor`.
pub fn doctor_line(results: &[HookCompatibility]) -> String {
    let checks = results
        .iter()
        .map(|r| format!("{}={}", r.hook.func(), r.status.word()))
        .collect::<Vec<_>>()
        .join(", ");
    let rejected: Vec<&HookCompatibility> = results
        .iter()
        .filter(|r| r.status != Compatibility::Compatible)
        .collect();
    let incompatible: Vec<&HookCompatibility> = results
        .iter()
        .filter(|r| r.status == Compatibility::Incompatible)
        .collect();
    let unknown: Vec<&HookCompatibility> = results
        .iter()
        .filter(|r| r.status == Compatibility::Unknown)
        .collect();
    let details = |rows: &[&HookCompatibility]| {
        rows.iter()
            .map(|r| format!("{}={} ({})", r.hook.func(), r.status.word(), r.reason()))
            .collect::<Vec<_>>()
            .join("; ")
    };
    let verdict = if rejected.is_empty() {
        "All six prototypes match this build, so aya may attempt each fexit; this still says \
         nothing about verifier acceptance, attach, or a landed bump."
            .to_string()
    } else {
        let mut parts = Vec::new();
        if !incompatible.is_empty() {
            parts.push(format!(
                "{} of six hook(s) are INCOMPATIBLE and will be skipped: {}",
                incompatible.len(),
                details(&incompatible)
            ));
        }
        if !unknown.is_empty() {
            parts.push(format!(
                "{} of six hook(s) are UNKNOWN — {} — which does NOT block an attach attempt",
                unknown.len(),
                details(&unknown)
            ));
        }
        format!(
            "{}. A named INCOMPATIBLE is a decision the loader made; UNKNOWN is an absence of \
             evidence, not a refusal.",
            parts.join(". ")
        )
    };
    format!("warden: doctor: volume fexit BTF ABI preflight: {checks}. {verdict}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add_string(strings: &mut Vec<u8>, s: &str) -> u32 {
        let off = strings.len() as u32;
        strings.extend_from_slice(s.as_bytes());
        strings.push(0);
        off
    }

    fn type_bytes(name_off: u32, kind: u32, vlen: u32, data: u32, extra: &[u8]) -> Vec<u8> {
        let info = (vlen & 0xffff) | (kind << 24);
        let mut out = Vec::new();
        out.extend_from_slice(&name_off.to_le_bytes());
        out.extend_from_slice(&info.to_le_bytes());
        out.extend_from_slice(&data.to_le_bytes());
        out.extend_from_slice(extra);
        out
    }

    /// A minimal kernel BTF with one compatible `tcp_sendmsg` prototype. Enough
    /// to prove the parser reads type ids, string offsets and FUNC_PROTO params
    /// correctly without depending on whatever kernel the test host runs.
    fn synthetic_btf(recv_arg_count: u32) -> Vec<u8> {
        let mut strings = vec![0];
        let size_t = add_string(&mut strings, "size_t");
        let sock = add_string(&mut strings, "sock");
        let msghdr = add_string(&mut strings, "msghdr");
        let func = add_string(&mut strings, "tcp_sendmsg");
        let datasec = add_string(&mut strings, "m15_datasec");
        let variable = add_string(&mut strings, "m15_var");
        let enum64 = add_string(&mut strings, "m15_enum64");

        let mut types = Vec::new();
        // BTF_KIND_INT carries one trailing encoding word and has vlen 1.
        types.extend(type_bytes(size_t, KIND_INT, 1, 8, &0u32.to_le_bytes())); // 1
        types.extend(type_bytes(sock, KIND_STRUCT, 0, 0, &[])); // 2
        types.extend(type_bytes(0, KIND_PTR, 0, 2, &[])); // 3 -> sock
        types.extend(type_bytes(msghdr, KIND_STRUCT, 0, 0, &[])); // 4
        types.extend(type_bytes(0, KIND_PTR, 0, 4, &[])); // 5 -> msghdr
        types.extend(type_bytes(func, KIND_FUNC, 0, 7, &[])); // 6 -> proto 7

        let mut params = Vec::new();
        for (name_off, type_id) in [(0u32, 3u32), (0, 5), (0, 1)]
            .into_iter()
            .take(recv_arg_count as usize)
        {
            params.extend_from_slice(&name_off.to_le_bytes());
            params.extend_from_slice(&type_id.to_le_bytes());
        }
        types.extend(type_bytes(0, KIND_FUNC_PROTO, recv_arg_count, 1, &params)); // 7
                                                                                  // These four kinds are the exact byte-accounting defects the real BTF
                                                                                  // files exposed. A DATASEC entry is 12 bytes, a TYPE_TAG has no trailing
                                                                                  // word, a VAR has one, and an ENUM64 variant is 12 bytes (its 64-bit
                                                                                  // value is two words). A wrong size shifts every later type id until a
                                                                                  // real kernel fails with "12-byte base is truncated".
        let mut secinfo = Vec::new();
        secinfo.extend_from_slice(&1u32.to_le_bytes()); // btf_type
        secinfo.extend_from_slice(&0u32.to_le_bytes()); // offset
        secinfo.extend_from_slice(&8u32.to_le_bytes()); // size
        types.extend(type_bytes(datasec, KIND_DATASEC, 1, 8, &secinfo)); // 8
        types.extend(type_bytes(0, KIND_TYPE_TAG, 0, 1, &[])); // 9
        types.extend(type_bytes(variable, KIND_VAR, 0, 1, &1u32.to_le_bytes())); // 10
        let mut enum_value = Vec::new();
        enum_value.extend_from_slice(&enum64.to_le_bytes());
        enum_value.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        enum_value.extend_from_slice(&0u32.to_le_bytes());
        types.extend(type_bytes(enum64, KIND_ENUM64, 1, 4, &enum_value)); // 11

        let mut out = Vec::new();
        out.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        out.push(1); // version
        out.push(0); // flags
        out.extend_from_slice(&24u32.to_le_bytes()); // hdr_len
        out.extend_from_slice(&0u32.to_le_bytes()); // type_off
        out.extend_from_slice(&(types.len() as u32).to_le_bytes()); // type_len
        out.extend_from_slice(&(types.len() as u32).to_le_bytes()); // str_off
        out.extend_from_slice(&(strings.len() as u32).to_le_bytes()); // str_len
        out.extend_from_slice(&types);
        out.extend_from_slice(&strings);
        out
    }

    #[test]
    fn a_raw_btf_prototype_is_read_and_compared_without_loading_anything() {
        // Pin the wire magic independently of the constant: transposing 0xeb9f
        // into 0xebf9 still lets a self-consistent synthetic fixture pass, and
        // only the live doctor run exposed it. The two header bytes on disk are
        // `9f eb` (od -An -tx1 -N2 /sys/kernel/btf/vmlinux).
        let bytes = synthetic_btf(3);
        assert_eq!(&bytes[..2], &[0x9f, 0xeb], "BTF magic bytes on disk");
        assert_eq!(BTF_MAGIC, 0xeb9f);
        let btf = RawBtf::parse(&bytes).expect("synthetic BTF parses");
        let result = check_against(&btf, VolumeHook::TcpSendMsg);
        assert_eq!(
            result.status,
            Compatibility::Compatible,
            "{}",
            result.reason()
        );
        assert!(result.reason().contains("sock *"));
        assert!(result.reason().contains("msghdr *"));
    }

    #[test]
    fn a_wrong_argument_count_is_an_explicit_incompatibility_not_a_silent_attach_attempt() {
        let btf = RawBtf::parse(&synthetic_btf(2)).expect("synthetic BTF parses");
        let result = check_against(&btf, VolumeHook::TcpSendMsg);
        assert_eq!(result.status, Compatibility::Incompatible);
        assert!(result.reason().contains("2 arguments"));
        assert!(result.reason().contains("3"));
    }

    /// A real kernel BTF is the only fixture large enough to desynchronise type
    /// ids the way the target did. On a machine without BTF this records a
    /// skip; in the M15 lab it runs against `/sys/kernel/btf/vmlinux`. Setting
    /// `WARDEN_M15_REQUIRE_COMPATIBLE=1` additionally pins the six signatures
    /// to this build, which is what the post-fix VM evidence does.
    #[test]
    fn a_real_vmlinux_btf_parses_and_checks_all_six_hooks() {
        let path = std::env::var("WARDEN_M15_TARGET_BTF").unwrap_or_else(|_| BTF_PATH.to_string());
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("skip: real BTF {path} unavailable: {e}");
                return;
            }
        };
        let btf = RawBtf::parse(&bytes).unwrap_or_else(|e| panic!("real BTF {path} parses: {e}"));
        let results: Vec<HookCompatibility> = VolumeHook::ALL
            .iter()
            .map(|&hook| check_against(&btf, hook))
            .collect();
        assert!(
            results.iter().all(|r| r.status != Compatibility::Unknown),
            "a parsed BTF must yield decisions, not unknowns: {}",
            doctor_line(&results)
        );
        if std::env::var_os("WARDEN_M15_REQUIRE_COMPATIBLE").is_some() {
            assert!(
                results
                    .iter()
                    .all(|r| r.status == Compatibility::Compatible),
                "target BTF {path} must match all six build prototypes: {}",
                results
                    .iter()
                    .map(|r| format!("{} ({})", r.hook.func(), r.reason()))
                    .collect::<Vec<_>>()
                    .join("; ")
            );
        }
    }

    #[test]
    fn an_unreadable_btf_is_unknown_for_every_hook() {
        let results = check_all("/nonexistent/m15/btf");
        assert_eq!(results.len(), 6);
        assert!(results.iter().all(|r| r.status == Compatibility::Unknown));
        assert!(results.iter().all(|r| !r.status.blocks_attach()));
    }

    fn proto_param(type_id: u32) -> [u8; 8] {
        let mut param = [0u8; 8];
        param[4..].copy_from_slice(&type_id.to_le_bytes());
        param
    }

    #[test]
    fn as_chunks_parameter_extraction_preserves_exact_chunk_semantics() {
        // One complete chunk, no remainder.
        assert_eq!(prototype_param_type_ids(&proto_param(7), 1), vec![7]);

        // Multiple complete chunks, no remainder.
        let three = [proto_param(1), proto_param(2), proto_param(3)].concat();
        assert_eq!(prototype_param_type_ids(&three, 3), vec![1, 2, 3]);

        // A non-empty remainder must be ignored exactly as `chunks_exact` did.
        let mut with_remainder = proto_param(9).to_vec();
        with_remainder.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        assert_eq!(prototype_param_type_ids(&with_remainder, 1), vec![9]);

        // No complete chunks: neither an empty request nor a declared argument
        // can manufacture a type id out of partial bytes.
        let partial = [0xaa, 0xbb, 0xcc];
        assert!(prototype_param_type_ids(&partial, 0).is_empty());
        assert!(prototype_param_type_ids(&partial, 1).is_empty());

        // Truncated input yields only the complete chunks; the caller's existing
        // declared-vs-observed count check still turns that into an error.
        let mut truncated = proto_param(1).to_vec();
        truncated.extend_from_slice(&[0, 0]);
        assert_eq!(prototype_param_type_ids(&truncated, 2), vec![1]);
        assert!(prototype_param_type_ids(&[], usize::MAX).is_empty());
    }

    #[test]
    fn a_short_prototype_argument_area_is_still_an_explicit_incompatibility() {
        // The parser sizes FUNC_PROTO trailing bytes as 8 * vlen, so a short
        // area appears as a lower observed argument count. This pins the
        // behaviour that a truncated parameter list is never a silent match.
        let btf = RawBtf::parse(&synthetic_btf(2)).expect("synthetic BTF parses");
        let result = check_against(&btf, VolumeHook::TcpSendMsg);
        assert_eq!(result.status, Compatibility::Incompatible);
        assert!(result.reason().contains("2 arguments"));
    }
}
