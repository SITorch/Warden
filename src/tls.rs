//! tls.rs — optional mutual TLS for the Sentinel bridge, without a TLS crate.
//!
//! Phase 8 needs the agent to authenticate with its OWN certificate, not with a
//! shared `X-API-Key` string. The offline build has no rustls/native-tls crate
//! available, so this module binds directly to the system OpenSSL 3 library
//! through `extern "C"` declarations. There is no new Cargo dependency and no
//! `Cargo.lock` change; the dynamic-library dependency is explicit and is only
//! linked when this module is compiled into the binary.
//!
//! Safety contract:
//!
//! * `SSL_CTX` is created only from explicit CA/cert/key files and is never
//!   populated from ambient system trust by accident.
//! * Peer verification is mandatory (`SSL_VERIFY_PEER`). The destination is
//!   pinned on the per-connection `SSL` object: DNS names through
//!   `X509_VERIFY_PARAM_set1_host`, IP literals through
//!   `X509_VERIFY_PARAM_set1_ip_asc`. SNI is sent only for DNS names. The shared
//!   `SSL_CTX` verification parameters are never mutated per connection, so
//!   concurrent attempts cannot contaminate each other. There is no "verify
//!   off" spelling.
//! * The private key is read by OpenSSL from a path; its bytes are never copied
//!   into a Rust string, a log line, an envelope, or the spool.
//! * Every raw pointer is owned and freed on exactly one path. `SSL_CTX` is
//!   shared read-only across delivery retries; `SSL` belongs to one attempt.

use std::ffi::{c_char, c_int, c_long, c_ulong, c_void, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::ptr;
use std::time::Duration;

use anyhow::{anyhow, Context};

// Values from <openssl/ssl.h> / <openssl/x509_vfy.h> / <openssl/err.h>.
const SSL_VERIFY_PEER: c_int = 0x01;
const SSL_FILETYPE_PEM: c_int = 1;
const SSL_CTRL_SET_TLSEXT_HOSTNAME: c_int = 55;
const TLSEXT_NAMETYPE_HOST_NAME: c_long = 0;
const SSL_ERROR_NONE: c_int = 0;
const SSL_ERROR_SSL: c_int = 1;
const SSL_ERROR_WANT_READ: c_int = 2;
const SSL_ERROR_WANT_WRITE: c_int = 3;
const SSL_ERROR_SYSCALL: c_int = 5;
const SSL_ERROR_ZERO_RETURN: c_int = 6;
const X509_V_OK: c_long = 0;

#[allow(clippy::upper_case_acronyms)]
#[repr(C)]
struct SSL_CTX {
    _private: [u8; 0],
}
#[allow(clippy::upper_case_acronyms)]
#[repr(C)]
struct SSL {
    _private: [u8; 0],
}
#[repr(C)]
struct SSL_METHOD {
    _private: [u8; 0],
}
#[repr(C)]
struct X509_VERIFY_PARAM {
    _private: [u8; 0],
}

#[link(name = "ssl")]
extern "C" {
    fn TLS_client_method() -> *const SSL_METHOD;
    fn SSL_CTX_new(method: *const SSL_METHOD) -> *mut SSL_CTX;
    fn SSL_CTX_free(ctx: *mut SSL_CTX);
    fn SSL_CTX_set_verify(
        ctx: *mut SSL_CTX,
        mode: c_int,
        callback: Option<unsafe extern "C" fn(c_int, *mut c_void) -> c_int>,
    );
    fn SSL_CTX_load_verify_locations(
        ctx: *mut SSL_CTX,
        ca_file: *const c_char,
        ca_path: *const c_char,
    ) -> c_int;
    fn SSL_CTX_use_certificate_file(
        ctx: *mut SSL_CTX,
        file: *const c_char,
        file_type: c_int,
    ) -> c_int;
    fn SSL_CTX_use_PrivateKey_file(
        ctx: *mut SSL_CTX,
        file: *const c_char,
        file_type: c_int,
    ) -> c_int;
    fn SSL_CTX_check_private_key(ctx: *const SSL_CTX) -> c_int;
    fn SSL_new(ctx: *mut SSL_CTX) -> *mut SSL;
    /// Returns the verification-parameter object owned by this SSL object.
    /// OpenSSL 1.1.0+ gives each SSL a copy at `SSL_new`, so mutating it cannot
    /// change the shared SSL_CTX or another in-flight connection.
    fn SSL_get0_param(ssl: *mut SSL) -> *mut X509_VERIFY_PARAM;
    fn SSL_free(ssl: *mut SSL);
    fn SSL_set_fd(ssl: *mut SSL, fd: c_int) -> c_int;
    fn SSL_ctrl(ssl: *mut SSL, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    fn SSL_connect(ssl: *mut SSL) -> c_int;
    fn SSL_shutdown(ssl: *mut SSL) -> c_int;
    fn SSL_read(ssl: *mut SSL, buf: *mut c_void, num: c_int) -> c_int;
    fn SSL_write(ssl: *mut SSL, buf: *const c_void, num: c_int) -> c_int;
    /// PRQ-01: OpenSSL error classification MUST use the return of SSL_get_error
    /// (which takes the SSL object and the raw SSL_read/SSL_write result), not the
    /// raw result itself — the two integer domains are unrelated.
    fn SSL_get_error(ssl: *mut SSL, ret: c_int) -> c_int;
    fn SSL_get_verify_result(ssl: *const SSL) -> c_long;
}

#[link(name = "crypto")]
extern "C" {
    fn X509_VERIFY_PARAM_set1_host(
        param: *mut X509_VERIFY_PARAM,
        name: *const c_char,
        name_len: usize,
    ) -> c_int;
    /// Verifies an IP literal against the certificate's iPAddress SANs. Passing
    /// an IP to `set1_host` would ask OpenSSL for a DNS-name match, which is why
    /// the two destination forms must be separated explicitly.
    fn X509_VERIFY_PARAM_set1_ip_asc(param: *mut X509_VERIFY_PARAM, ipasc: *const c_char) -> c_int;
    fn ERR_get_error() -> c_ulong;
    fn ERR_error_string_n(e: c_ulong, buf: *mut c_char, len: usize);
}

/// Drain OpenSSL's per-thread error queue into a message. Error strings describe
/// the failure class; they never contain the key bytes read from disk.
fn openssl_error() -> String {
    let mut message = vec![0u8; 256];
    let code = unsafe { ERR_get_error() };
    if code == 0 {
        return "OpenSSL reported an error without a queue entry".to_string();
    }
    unsafe {
        ERR_error_string_n(code, message.as_mut_ptr() as *mut c_char, message.len());
    }
    let end = message
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(message.len());
    String::from_utf8_lossy(&message[..end]).into_owned()
}

fn path_text(path: &Path, label: &str) -> anyhow::Result<CString> {
    let text = path
        .to_str()
        .ok_or_else(|| anyhow!("{label} path is not valid UTF-8"))?;
    CString::new(text).with_context(|| format!("{label} path contains a NUL byte"))
}

/// Shared TLS material. Constructed once when the delivery thread starts.
pub struct TlsContext {
    ctx: *mut SSL_CTX,
}

// OpenSSL 1.1+ SSL_CTX objects are safe to share between threads for the purpose
// of creating per-connection SSL objects. Each attempt owns its own SSL and fd.
unsafe impl Send for TlsContext {}
unsafe impl Sync for TlsContext {}

impl TlsContext {
    /// Load CA certificate, client certificate and client key from explicit
    /// paths. Any failure is fatal at startup — a bridge that claims mTLS but
    /// silently falls back to cleartext is worse than no bridge.
    pub fn new(ca_file: &Path, cert_file: &Path, key_file: &Path) -> anyhow::Result<Self> {
        for (label, path) in [
            ("CA certificate", ca_file),
            ("client certificate", cert_file),
            ("client key", key_file),
        ] {
            File::open(path)
                .with_context(|| format!("cannot open {label} at {}", path.display()))?;
        }

        let ctx = unsafe { SSL_CTX_new(TLS_client_method()) };
        if ctx.is_null() {
            return Err(anyhow!("SSL_CTX_new failed: {}", openssl_error()));
        }
        let loaded = (|| -> anyhow::Result<()> {
            let ca = path_text(ca_file, "CA certificate")?;
            let cert = path_text(cert_file, "client certificate")?;
            let key = path_text(key_file, "client key")?;
            unsafe {
                if SSL_CTX_load_verify_locations(ctx, ca.as_ptr(), ptr::null()) != 1 {
                    return Err(anyhow!(
                        "cannot load bridge TLS CA {}: {}",
                        ca_file.display(),
                        openssl_error()
                    ));
                }
                if SSL_CTX_use_certificate_file(ctx, cert.as_ptr(), SSL_FILETYPE_PEM) != 1 {
                    return Err(anyhow!(
                        "cannot load bridge TLS client certificate {}: {}",
                        cert_file.display(),
                        openssl_error()
                    ));
                }
                if SSL_CTX_use_PrivateKey_file(ctx, key.as_ptr(), SSL_FILETYPE_PEM) != 1 {
                    return Err(anyhow!(
                        "cannot load bridge TLS client key {}: {}",
                        key_file.display(),
                        openssl_error()
                    ));
                }
                if SSL_CTX_check_private_key(ctx) != 1 {
                    return Err(anyhow!(
                        "bridge TLS client certificate and key do not match: {}",
                        openssl_error()
                    ));
                }
                // Mandatory peer authentication. No option exists to turn this
                // off: an mTLS bridge that accepts an unverified server is not
                // mTLS.
                SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, None);
            }
            Ok(())
        })();
        if let Err(e) = loaded {
            unsafe { SSL_CTX_free(ctx) };
            return Err(e);
        }
        Ok(Self { ctx })
    }

    /// Perform the TLS handshake on an already-connected TCP stream.
    ///
    /// `hostname` is the identity to authenticate, not a hint. A DNS name is
    /// matched against DNS SANs and sent as SNI; an IP literal is matched
    /// against iPAddress SANs and sends no SNI. All verification parameters are
    /// set on this SSL object only.
    pub fn connect(&self, stream: TcpStream, hostname: &str) -> anyhow::Result<TlsStream> {
        let host =
            CString::new(hostname).with_context(|| "bridge TLS hostname contains a NUL byte")?;
        let ip_literal = hostname.parse::<IpAddr>().ok();
        let ssl = unsafe { SSL_new(self.ctx) };
        if ssl.is_null() {
            return Err(anyhow!("SSL_new failed: {}", openssl_error()));
        }
        let ok = (|| -> anyhow::Result<()> {
            unsafe {
                if SSL_set_fd(ssl, stream.as_raw_fd()) != 1 {
                    return Err(anyhow!("SSL_set_fd failed: {}", openssl_error()));
                }
                // This must be SSL_get0_param(ssl), never SSL_CTX_get0_param(ctx):
                // the latter would leak one connection's hostname into every
                // later and concurrent connection built from the shared context.
                let param = SSL_get0_param(ssl);
                if param.is_null() {
                    return Err(anyhow!(
                        "SSL object has no verification parameters for {hostname:?}"
                    ));
                }
                match ip_literal {
                    Some(_) => {
                        if X509_VERIFY_PARAM_set1_ip_asc(param, host.as_ptr()) != 1 {
                            return Err(anyhow!(
                                "cannot pin bridge TLS IP literal {hostname:?}: {}",
                                openssl_error()
                            ));
                        }
                        // RFC 6066: SNI is a DNS name. Sending one for an IP
                        // literal is not meaningful and is explicitly forbidden
                        // by the bridge contract.
                    }
                    None => {
                        if X509_VERIFY_PARAM_set1_host(param, host.as_ptr(), 0) != 1 {
                            return Err(anyhow!(
                                "cannot pin bridge TLS hostname {hostname:?}: {}",
                                openssl_error()
                            ));
                        }
                        if SSL_ctrl(
                            ssl,
                            SSL_CTRL_SET_TLSEXT_HOSTNAME,
                            TLSEXT_NAMETYPE_HOST_NAME,
                            host.as_ptr() as *mut c_void,
                        ) != 1
                        {
                            return Err(anyhow!(
                                "cannot set bridge TLS SNI {hostname:?}: {}",
                                openssl_error()
                            ));
                        }
                    }
                }
                if SSL_connect(ssl) != 1 {
                    return Err(anyhow!("bridge TLS handshake failed: {}", openssl_error()));
                }
                let verify = SSL_get_verify_result(ssl);
                if verify != X509_V_OK {
                    return Err(anyhow!(
                        "bridge TLS peer certificate verification failed (code {verify})"
                    ));
                }
            }
            Ok(())
        })();
        if let Err(e) = ok {
            unsafe {
                SSL_free(ssl);
            }
            return Err(e);
        }
        Ok(TlsStream {
            ssl,
            stream,
            _host: host,
        })
    }
}

impl std::fmt::Debug for TlsContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TlsContext { ctx: <opaque OpenSSL context> }")
    }
}

impl Drop for TlsContext {
    fn drop(&mut self) {
        unsafe { SSL_CTX_free(self.ctx) };
    }
}

/// One TLS connection. Implements `Read`/`Write` so the existing HTTP/1.1 code
/// can stay byte-for-byte the same on both transports.
pub struct TlsStream {
    ssl: *mut SSL,
    /// Keeps the file descriptor alive for the life of the SSL object.
    stream: TcpStream,
    /// Keep SNI storage alive until the handshake has completed.
    _host: CString,
}

impl TlsStream {
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }

    /// PRQ-01: map the *classified* result from SSL_get_error, not the raw
    /// SSL_read/SSL_write return. Previously the raw return (typically -1) was
    /// matched against SSL_ERROR_* codes, making ZERO_RETURN/WANT_READ/WANT_WRITE
    /// unreachable and misreporting clean TLS closure and timeouts as generic
    /// OpenSSL errors. The socket timeout is preserved as WouldBlock/TimedOut so
    /// bridge retry logic can distinguish an expected close from a failure.
    fn last_error(&self, raw: c_int) -> io::Error {
        let kind = unsafe { SSL_get_error(self.ssl, raw) };
        match kind {
            SSL_ERROR_ZERO_RETURN => io::Error::new(io::ErrorKind::UnexpectedEof, "TLS closed"),
            SSL_ERROR_WANT_READ | SSL_ERROR_WANT_WRITE => {
                let io_err = std::io::Error::last_os_error();
                if io_err.kind() == io::ErrorKind::TimedOut {
                    io_err
                } else {
                    io::Error::new(io::ErrorKind::WouldBlock, "TLS socket would block")
                }
            }
            SSL_ERROR_SYSCALL => io::Error::last_os_error(),
            SSL_ERROR_SSL | SSL_ERROR_NONE => io::Error::other(openssl_error()),
            other => io::Error::other(format!(
                "unexpected OpenSSL transport result {other}: {}",
                openssl_error()
            )),
        }
    }
}

impl Drop for TlsStream {
    fn drop(&mut self) {
        unsafe {
            let _ = SSL_shutdown(self.ssl);
            SSL_free(self.ssl);
        }
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = buf.len().min(c_int::MAX as usize) as c_int;
        let n = unsafe { SSL_read(self.ssl, buf.as_mut_ptr() as *mut c_void, len) };
        if n > 0 {
            Ok(n as usize)
        } else {
            Err(self.last_error(n))
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = buf.len().min(c_int::MAX as usize) as c_int;
        let n = unsafe { SSL_write(self.ssl, buf.as_ptr() as *const c_void, len) };
        if n > 0 {
            Ok(n as usize)
        } else {
            Err(self.last_error(n))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // SSL_write is synchronous once it returns; the socket has no userspace
        // buffer that could still be pending here.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddr, TcpListener};
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    fn openssl(args: &[&str]) -> bool {
        Command::new("openssl")
            .args(args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn run_openssl(args: &[&str]) {
        let out = Command::new("openssl")
            .args(args)
            .output()
            .expect("openssl must be available for the mandatory TLS matrix");
        // A failing OpenSSL invocation must not print its argv: those values
        // include private-key and certificate paths. The allowlisted flag/command
        // summary keeps enough context to identify the failing test step.
        assert!(
            out.status.success(),
            "openssl command failed ({})",
            crate::safe_log::safe_command_summary(args)
        );
    }

    #[test]
    fn openssl_diagnostics_do_not_echo_private_key_paths() {
        const KEY_PATH_CANARY: &str = "/tmp/CANARY_NOT_REAL_PRIVATE_KEY_PATH_2b17.pem";
        let summary = crate::safe_log::safe_command_summary(&[
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-keyout",
            KEY_PATH_CANARY,
            "-subj",
            "/CN=warden-agent",
        ]);
        assert!(
            !summary.contains(KEY_PATH_CANARY),
            "command diagnostics must not echo the key path"
        );
        assert!(summary.contains("req"));
        assert!(summary.contains("-keyout"));
    }

    struct Fixtures {
        dir: PathBuf,
        ca: PathBuf,
        ca_key: PathBuf,
        client_cert: PathBuf,
        client_key: PathBuf,
        next_serial: u64,
    }

    impl Fixtures {
        fn new(tag: &str) -> Self {
            assert!(
                openssl(&["version"]),
                "OpenSSL CLI is required for TLS tests"
            );
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir()
                .join(format!("warden-tls-{tag}-{}-{unique}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let ca = dir.join("ca.pem");
            let ca_key = dir.join("ca.key");
            run_openssl(&[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "2",
                "-keyout",
                ca_key.to_str().unwrap(),
                "-out",
                ca.to_str().unwrap(),
                "-subj",
                "/CN=warden-test-ca",
            ]);
            let client_cert = dir.join("client.pem");
            let client_key = dir.join("client.key");
            let client_csr = dir.join("client.csr");
            let client_ext = dir.join("client-ext.cnf");
            std::fs::write(&client_ext, "[client]\nextendedKeyUsage=clientAuth\n").unwrap();
            run_openssl(&[
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                client_key.to_str().unwrap(),
                "-out",
                client_csr.to_str().unwrap(),
                "-subj",
                "/CN=warden-agent",
            ]);
            run_openssl(&[
                "x509",
                "-req",
                "-in",
                client_csr.to_str().unwrap(),
                "-CA",
                ca.to_str().unwrap(),
                "-CAkey",
                ca_key.to_str().unwrap(),
                "-set_serial",
                "10",
                "-days",
                "1",
                "-extfile",
                client_ext.to_str().unwrap(),
                "-extensions",
                "client",
                "-out",
                client_cert.to_str().unwrap(),
            ]);
            Self {
                dir,
                ca,
                ca_key,
                client_cert,
                client_key,
                next_serial: 100,
            }
        }

        fn context(&self) -> TlsContext {
            TlsContext::new(&self.ca, &self.client_cert, &self.client_key)
                .expect("valid client material must load")
        }

        fn serial(&mut self) -> u64 {
            let n = self.next_serial;
            self.next_serial += 1;
            n
        }

        fn sign_server(&mut self, name: &str, san: &str) -> (PathBuf, PathBuf) {
            let cert = self.dir.join(format!("{name}.pem"));
            let key = self.dir.join(format!("{name}.key"));
            let csr = self.dir.join(format!("{name}.csr"));
            let ext = self.dir.join(format!("{name}-san.cnf"));
            std::fs::write(&ext, format!("[v3]\nsubjectAltName={san}\n")).unwrap();
            run_openssl(&[
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                key.to_str().unwrap(),
                "-out",
                csr.to_str().unwrap(),
                "-subj",
                &format!("/CN={name}"),
            ]);
            let serial = self.serial().to_string();
            run_openssl(&[
                "x509",
                "-req",
                "-in",
                csr.to_str().unwrap(),
                "-CA",
                self.ca.to_str().unwrap(),
                "-CAkey",
                self.ca_key.to_str().unwrap(),
                "-set_serial",
                &serial,
                "-days",
                "1",
                "-extfile",
                ext.to_str().unwrap(),
                "-extensions",
                "v3",
                "-out",
                cert.to_str().unwrap(),
            ]);
            (cert, key)
        }

        fn sign_server_with_untrusted_ca(&self, name: &str, san: &str) -> (PathBuf, PathBuf) {
            let ca = self.dir.join(format!("{name}-other-ca.pem"));
            let ca_key = self.dir.join(format!("{name}-other-ca.key"));
            run_openssl(&[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "2",
                "-keyout",
                ca_key.to_str().unwrap(),
                "-out",
                ca.to_str().unwrap(),
                "-subj",
                "/CN=warden-untrusted-ca",
            ]);
            let key = self.dir.join(format!("{name}.key"));
            let csr = self.dir.join(format!("{name}.csr"));
            let ext = self.dir.join(format!("{name}-san.cnf"));
            std::fs::write(&ext, format!("[v3]\nsubjectAltName={san}\n")).unwrap();
            run_openssl(&[
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                key.to_str().unwrap(),
                "-out",
                csr.to_str().unwrap(),
                "-subj",
                &format!("/CN={name}"),
            ]);
            run_openssl(&[
                "x509",
                "-req",
                "-in",
                csr.to_str().unwrap(),
                "-CA",
                ca.to_str().unwrap(),
                "-CAkey",
                ca_key.to_str().unwrap(),
                "-set_serial",
                "900",
                "-days",
                "1",
                "-extfile",
                ext.to_str().unwrap(),
                "-extensions",
                "v3",
                "-out",
                self.dir.join(format!("{name}.pem")).to_str().unwrap(),
            ]);
            (self.dir.join(format!("{name}.pem")), key)
        }

        fn sign_expired_server(&self, name: &str, san: &str) -> (PathBuf, PathBuf) {
            let key = self.dir.join(format!("{name}.key"));
            let csr = self.dir.join(format!("{name}.csr"));
            let cert = self.dir.join(format!("{name}.pem"));
            let ext = self.dir.join(format!("{name}-san.cnf"));
            let db = self.dir.join(format!("{name}-index.txt"));
            let serial_file = self.dir.join(format!("{name}-serial"));
            let config = self.dir.join(format!("{name}-ca.cnf"));
            std::fs::write(&db, "").unwrap();
            std::fs::write(&serial_file, "1000\n").unwrap();
            std::fs::write(
                &config,
                format!(
                    "[ca]\ndefault_ca = CA_default\n[CA_default]\ndir = {}\n\
                     database = $dir/{}-index.txt\nnew_certs_dir = $dir\n\
                     serial = $dir/{}-serial\ndefault_md = sha256\npolicy = policy_any\n\
                     email_in_dn = no\nunique_subject = no\n\
                     [policy_any]\ncommonName = supplied\n",
                    self.dir.display(),
                    name,
                    name
                ),
            )
            .unwrap();
            std::fs::write(&ext, format!("[v3]\nsubjectAltName={san}\n")).unwrap();
            run_openssl(&[
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                key.to_str().unwrap(),
                "-out",
                csr.to_str().unwrap(),
                "-subj",
                &format!("/CN={name}"),
            ]);
            run_openssl(&[
                "ca",
                "-batch",
                "-config",
                config.to_str().unwrap(),
                "-cert",
                self.ca.to_str().unwrap(),
                "-keyfile",
                self.ca_key.to_str().unwrap(),
                "-in",
                csr.to_str().unwrap(),
                "-extfile",
                ext.to_str().unwrap(),
                "-extensions",
                "v3",
                "-startdate",
                "20200101000000Z",
                "-enddate",
                "20200102000000Z",
                "-notext",
                "-out",
                cert.to_str().unwrap(),
            ]);
            (cert, key)
        }
    }

    impl Drop for Fixtures {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    struct TlsServer {
        child: Child,
    }

    impl Drop for TlsServer {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn listen_port(ip: IpAddr) -> TcpListener {
        TcpListener::bind(SocketAddr::new(ip, 0)).unwrap()
    }

    fn spawn_server_on(
        listener: TcpListener,
        cert: &Path,
        key: &Path,
        ca: &Path,
    ) -> (TlsServer, u16) {
        let ip = listener.local_addr().unwrap().ip();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let accept = if ip.is_ipv6() {
            format!("[{ip}]:{port}")
        } else {
            format!("{ip}:{port}")
        };
        let child = Command::new("openssl")
            .args([
                "s_server",
                "-accept",
                &accept,
                "-cert",
                cert.to_str().unwrap(),
                "-key",
                key.to_str().unwrap(),
                "-CAfile",
                ca.to_str().unwrap(),
                "-Verify",
                "1",
                "-quiet",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("openssl s_server must start");
        let server = TlsServer { child };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if TcpStream::connect(SocketAddr::new(ip, port)).is_ok() {
                return (server, port);
            }
            if Instant::now() >= deadline {
                panic!("openssl s_server did not listen on {accept}");
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn connect_ok(ctx: &TlsContext, ip: IpAddr, port: u16, host: &str) {
        let tcp = TcpStream::connect(SocketAddr::new(ip, port)).unwrap();
        let tls = ctx
            .connect(tcp, host)
            .unwrap_or_else(|e| panic!("TLS to {host} should succeed: {e:#}"));
        drop(tls);
    }

    fn connect_err(ctx: &TlsContext, ip: IpAddr, port: u16, host: &str) -> String {
        let tcp = TcpStream::connect(SocketAddr::new(ip, port)).unwrap();
        match ctx.connect(tcp, host) {
            Ok(_) => panic!("TLS to {host} must be rejected"),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn missing_material_is_refused_without_touching_a_socket() {
        let dir = std::env::temp_dir();
        let missing = dir.join(format!("warden-tls-missing-{}", std::process::id()));
        let err = TlsContext::new(&missing, &missing, &missing).unwrap_err();
        let text = format!("{err:#}");
        assert!(
            text.contains("CA certificate"),
            "missing-material error must name the CA certificate"
        );
    }

    #[test]
    fn generated_client_material_loads_and_a_wrong_key_is_refused() {
        let f = Fixtures::new("keymatch");
        let _ = f.context();
        let wrong = f.dir.join("wrong.key");
        run_openssl(&["genrsa", "-out", wrong.to_str().unwrap(), "2048"]);
        assert!(TlsContext::new(&f.ca, &f.client_cert, &wrong).is_err());
    }

    #[test]
    fn trusted_ca_and_matching_dns_san_are_accepted() {
        let mut f = Fixtures::new("dns-ok");
        let (cert, key) = f.sign_server("dns-ok", "DNS:warden.test");
        let (server, port) = spawn_server_on(
            listen_port(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            &cert,
            &key,
            &f.ca,
        );
        connect_ok(
            &f.context(),
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
            "warden.test",
        );
        drop(server);
    }

    #[test]
    fn trusted_ca_with_wrong_dns_san_is_rejected() {
        let mut f = Fixtures::new("dns-wrong");
        let (cert, key) = f.sign_server("dns-wrong", "DNS:warden.test");
        let (server, port) = spawn_server_on(
            listen_port(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            &cert,
            &key,
            &f.ca,
        );
        let err = connect_err(
            &f.context(),
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
            "attacker.test",
        );
        assert!(
            err.contains("handshake") || err.contains("verification"),
            "{err}"
        );
        drop(server);
    }

    #[test]
    fn untrusted_ca_is_rejected() {
        let f = Fixtures::new("untrusted");
        let (cert, key) = f.sign_server_with_untrusted_ca("untrusted", "DNS:warden.test");
        let (server, port) = spawn_server_on(
            listen_port(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            &cert,
            &key,
            &f.ca,
        );
        let err = connect_err(
            &f.context(),
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
            "warden.test",
        );
        assert!(
            err.contains("certificate")
                || err.contains("verification")
                || err.contains("handshake"),
            "{err}"
        );
        drop(server);
    }

    #[test]
    fn expired_certificate_is_rejected() {
        let f = Fixtures::new("expired");
        let (cert, key) = f.sign_expired_server("expired", "DNS:warden.test");
        let (server, port) = spawn_server_on(
            listen_port(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            &cert,
            &key,
            &f.ca,
        );
        let err = connect_err(
            &f.context(),
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
            "warden.test",
        );
        assert!(
            err.contains("certificate")
                || err.contains("verification")
                || err.contains("handshake"),
            "{err}"
        );
        drop(server);
    }

    #[test]
    fn ipv4_ip_san_is_accepted() {
        let mut f = Fixtures::new("ipv4-ok");
        let (cert, key) = f.sign_server("ipv4-ok", "IP:127.0.0.1");
        let (server, port) = spawn_server_on(
            listen_port(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            &cert,
            &key,
            &f.ca,
        );
        connect_ok(
            &f.context(),
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
            "127.0.0.1",
        );
        drop(server);
    }

    #[test]
    fn ipv6_ip_san_is_accepted() {
        let mut f = Fixtures::new("ipv6-ok");
        let (cert, key) = f.sign_server("ipv6-ok", "IP:::1");
        let (server, port) = spawn_server_on(
            listen_port(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            &cert,
            &key,
            &f.ca,
        );
        connect_ok(
            &f.context(),
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            port,
            "::1",
        );
        drop(server);
    }

    #[test]
    fn mismatched_ip_san_is_rejected() {
        let mut f = Fixtures::new("ip-mismatch");
        let (cert, key) = f.sign_server("ip-mismatch", "IP:127.0.0.2");
        let (server, port) = spawn_server_on(
            listen_port(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            &cert,
            &key,
            &f.ca,
        );
        let err = connect_err(
            &f.context(),
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
            "127.0.0.1",
        );
        assert!(
            err.contains("handshake") || err.contains("verification"),
            "{err}"
        );
        drop(server);
    }

    #[test]
    fn dns_only_san_does_not_authenticate_an_ip_literal() {
        let mut f = Fixtures::new("ip-no-san");
        let (cert, key) = f.sign_server("ip-no-san", "DNS:warden.test");
        let (server, port) = spawn_server_on(
            listen_port(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            &cert,
            &key,
            &f.ca,
        );
        let err = connect_err(
            &f.context(),
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
            "127.0.0.1",
        );
        assert!(
            err.contains("handshake") || err.contains("verification"),
            "{err}"
        );
        drop(server);
    }

    #[test]
    fn failed_handshake_never_returns_a_stream_or_downgrades_to_http() {
        let mut f = Fixtures::new("downgrade");
        let (cert, key) = f.sign_server("downgrade", "DNS:warden.test");
        let listener = listen_port(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let port = listener.local_addr().unwrap().port();
        let recorder = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            buf[..n].to_vec()
        });
        let err = connect_err(
            &f.context(),
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
            "warden.test",
        );
        assert!(err.contains("handshake"), "{err}");
        let bytes = recorder.join().unwrap();
        assert!(!bytes.is_empty(), "a TLS ClientHello should have been sent");
        assert!(
            !String::from_utf8_lossy(&bytes)
                .to_ascii_uppercase()
                .contains("HTTP/"),
            "a failed TLS handshake must never emit an HTTP request"
        );
        drop((cert, key));
    }

    #[test]
    fn concurrent_connections_do_not_leak_verification_settings() {
        let mut f = Fixtures::new("concurrent");
        let (a_cert, a_key) = f.sign_server("host-a", "DNS:a.test");
        let (b_cert, b_key) = f.sign_server("host-b", "DNS:b.test");
        let (server_a, port_a) = spawn_server_on(
            listen_port(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            &a_cert,
            &a_key,
            &f.ca,
        );
        let (server_b, port_b) = spawn_server_on(
            listen_port(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            &b_cert,
            &b_key,
            &f.ca,
        );
        let ctx = Arc::new(f.context());
        let ip = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

        let check = |port: u16, host: &'static str, should_pass: bool| {
            let ctx = Arc::clone(&ctx);
            thread::spawn(move || {
                let result = (|| -> anyhow::Result<()> {
                    let tcp = TcpStream::connect(SocketAddr::new(ip, port))?;
                    let tls = ctx.connect(tcp, host)?;
                    drop(tls);
                    Ok(())
                })();
                result.is_ok() == should_pass
            })
        };
        let handles = vec![
            check(port_a, "a.test", true),
            check(port_b, "b.test", true),
            check(port_a, "b.test", false),
            check(port_b, "a.test", false),
        ];
        for (i, handle) in handles.into_iter().enumerate() {
            assert!(
                handle.join().unwrap(),
                "concurrent case {i} leaked verification state"
            );
        }
        drop((server_a, server_b));
    }
}
