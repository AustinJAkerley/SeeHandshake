// SPDX-License-Identifier: MIT

//! Linux `/proc`-based process attribution.
//!
//! Reads `/proc/net/tcp` and `/proc/net/tcp6` to map a TCP flow to a socket
//! inode, then walks `/proc/*/fd` to find the process owning that inode.
//! This is the technique `ss -tp` and `lsof -i` use.
//!
//! Results are cached for a short TTL so that a burst of new flows (e.g.
//! loading a page that opens ten sockets in a second) only walks `/proc`
//! once.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::origin::{Origin, OriginResolver, ProcessOrigin};

/// How long a `/proc` snapshot is trusted before being refreshed.
const CACHE_TTL_MS: u64 = 500;

/// Cap on cmdline length surfaced through [`ProcessOrigin`].
const CMDLINE_MAX_LEN: usize = 256;

/// State kept alive across `resolve` calls to amortize `/proc` walks.
pub struct LinuxProcResolver {
    root: PathBuf,
    cache: Option<Snapshot>,
    ttl: Duration,
}

struct Snapshot {
    taken_at: Instant,
    /// Socket table keyed on `(local, remote)`. The kernel only lists
    /// sockets whose local endpoint is on this machine, so a flow's
    /// direction can be recovered by trying both orderings.
    sockets: HashMap<(SocketAddr, SocketAddr), SocketRow>,
    /// Process table keyed on inode. Absent when the socket is owned by
    /// another user (their `/proc/<pid>/fd` is not readable).
    procs: HashMap<u64, ProcRow>,
}

#[derive(Clone, Debug)]
struct SocketRow {
    inode: u64,
    uid: u32,
}

#[derive(Clone, Debug)]
struct ProcRow {
    pid: u32,
    comm: String,
    cmdline: String,
    uid: u32,
}

impl Default for LinuxProcResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxProcResolver {
    /// Create a resolver rooted at `/`.
    #[must_use]
    pub fn new() -> Self {
        Self::with_root("/")
    }

    /// Create a resolver rooted at a custom path (test seam).
    #[must_use]
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            cache: None,
            ttl: Duration::from_millis(CACHE_TTL_MS),
        }
    }

    fn snapshot(&mut self) -> &Snapshot {
        let stale = self
            .cache
            .as_ref()
            .map_or(true, |s| s.taken_at.elapsed() >= self.ttl);
        if stale {
            let sockets = read_sockets(&self.root);
            let procs = read_procs(&self.root, &sockets);
            self.cache = Some(Snapshot {
                taken_at: Instant::now(),
                sockets,
                procs,
            });
        }
        self.cache.as_ref().unwrap()
    }
}

impl OriginResolver for LinuxProcResolver {
    fn resolve(&mut self, a: SocketAddr, b: SocketAddr) -> Origin {
        let snap = self.snapshot();
        let row = snap
            .sockets
            .get(&(a, b))
            .or_else(|| snap.sockets.get(&(b, a)));
        let Some(row) = row else {
            return Origin::Unknown;
        };
        if let Some(p) = snap.procs.get(&row.inode) {
            Origin::Local(ProcessOrigin {
                pid: p.pid,
                comm: p.comm.clone(),
                cmdline: p.cmdline.clone(),
                uid: p.uid,
            })
        } else {
            Origin::OtherUser { uid: row.uid }
        }
    }
}

fn read_sockets(root: &Path) -> HashMap<(SocketAddr, SocketAddr), SocketRow> {
    let mut out = HashMap::new();
    for name in &["proc/net/tcp", "proc/net/tcp6"] {
        let path = root.join(name);
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        parse_socket_table(&text, &mut out);
    }
    out
}

fn parse_socket_table(text: &str, out: &mut HashMap<(SocketAddr, SocketAddr), SocketRow>) {
    for line in text.lines().skip(1) {
        let Some((k, v)) = parse_socket_line(line) else {
            continue;
        };
        out.insert(k, v);
    }
}

/// Parse a single `/proc/net/tcp{,6}` row.
///
/// Kernel layout, one whitespace-separated token per field:
///
/// ```text
/// sl local:port remote:port state tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ...
/// ```
///
/// Note that `tx_queue:rx_queue` and `tr:tm->when` each pack two values
/// into a single colon-separated token — they take **one** whitespace
/// slot, not two. Getting this wrong shifts every subsequent field.
fn parse_socket_line(line: &str) -> Option<((SocketAddr, SocketAddr), SocketRow)> {
    let mut it = line.split_ascii_whitespace();
    let _sl = it.next()?;
    let local_hex = it.next()?;
    let remote_hex = it.next()?;
    let state = it.next()?;
    let _tx_rx = it.next()?;
    let _tr_tm = it.next()?;
    let _retr = it.next()?;
    let uid_s = it.next()?;
    let _timeout = it.next()?;
    let inode_s = it.next()?;

    // 01 = ESTABLISHED. Only established sockets carry the useful (local,
    // remote) pair we key on; LISTEN and TIME_WAIT rows are noise.
    if state != "01" {
        return None;
    }
    let local = parse_endpoint(local_hex)?;
    let remote = parse_endpoint(remote_hex)?;
    let uid = uid_s.parse::<u32>().ok()?;
    let inode = inode_s.parse::<u64>().ok()?;
    Some(((local, remote), SocketRow { inode, uid }))
}

fn parse_endpoint(s: &str) -> Option<SocketAddr> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = match addr_hex.len() {
        8 => IpAddr::V4(parse_ipv4_hex(addr_hex)?),
        32 => IpAddr::V6(parse_ipv6_hex(addr_hex)?),
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// IPv4 in `/proc/net/tcp` is the 32-bit address written in host byte
/// order — on little-endian systems that means the bytes appear reversed:
/// `0100007F` = `127.0.0.1`.
fn parse_ipv4_hex(s: &str) -> Option<Ipv4Addr> {
    let raw = u32::from_str_radix(s, 16).ok()?;
    let b = raw.to_le_bytes();
    Some(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
}

/// IPv6 in `/proc/net/tcp6` is four 32-bit words, each written in host
/// byte order. On little-endian systems each 8-hex-char word must be
/// byte-reversed to recover the network-order 4 bytes.
fn parse_ipv6_hex(s: &str) -> Option<Ipv6Addr> {
    let mut bytes = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks_exact(8).enumerate() {
        let word_hex = std::str::from_utf8(chunk).ok()?;
        let raw = u32::from_str_radix(word_hex, 16).ok()?;
        let le = raw.to_le_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&le);
    }
    Some(Ipv6Addr::from(bytes))
}

fn read_procs(
    root: &Path,
    sockets: &HashMap<(SocketAddr, SocketAddr), SocketRow>,
) -> HashMap<u64, ProcRow> {
    let mut wanted: std::collections::HashSet<u64> = sockets.values().map(|r| r.inode).collect();
    let mut out = HashMap::new();
    let proc_root = root.join("proc");
    let Ok(entries) = fs::read_dir(&proc_root) else {
        return out;
    };
    for entry in entries.flatten() {
        if wanted.is_empty() {
            break;
        }
        let name = entry.file_name();
        let Some(name_s) = name.to_str() else {
            continue;
        };
        let Ok(pid) = name_s.parse::<u32>() else {
            continue;
        };
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let Some(inode) = socket_inode_from_link(&target) else {
                continue;
            };
            if !wanted.contains(&inode) {
                continue;
            }
            let comm = read_comm(&entry.path());
            let cmdline = read_cmdline(&entry.path());
            let uid = read_uid(&entry.path()).unwrap_or(0);
            out.insert(
                inode,
                ProcRow {
                    pid,
                    comm,
                    cmdline,
                    uid,
                },
            );
            wanted.remove(&inode);
            if wanted.is_empty() {
                break;
            }
        }
    }
    out
}

fn socket_inode_from_link(target: &Path) -> Option<u64> {
    let s = target.to_str()?;
    let inner = s.strip_prefix("socket:[")?.strip_suffix(']')?;
    inner.parse().ok()
}

fn read_comm(pid_dir: &Path) -> String {
    fs::read_to_string(pid_dir.join("comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn read_cmdline(pid_dir: &Path) -> String {
    let raw = fs::read(pid_dir.join("cmdline")).unwrap_or_default();
    let mut s: String = raw
        .into_iter()
        .map(|b| if b == 0 { ' ' } else { b as char })
        .collect();
    let trimmed = s.trim_end();
    s.truncate(trimmed.len());
    if s.len() > CMDLINE_MAX_LEN {
        s.truncate(CMDLINE_MAX_LEN);
        s.push_str("...");
    }
    s
}

fn read_uid(pid_dir: &Path) -> Option<u32> {
    let text = fs::read_to_string(pid_dir.join("status")).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_ascii_whitespace().next()?.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_hex_is_host_byte_order() {
        assert_eq!(
            parse_ipv4_hex("0100007F"),
            Some(Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(
            parse_ipv4_hex("0101A8C0"),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn ipv6_hex_loopback() {
        assert_eq!(
            parse_ipv6_hex("00000000000000000000000001000000"),
            Some(Ipv6Addr::LOCALHOST)
        );
    }

    #[test]
    fn ipv6_hex_global_address() {
        // 2601:0600:9280:6B50:595C:721F:B469:E80E
        let addr = parse_ipv6_hex("00060126506B80921F725C590EE869B4").unwrap();
        assert_eq!(
            addr,
            Ipv6Addr::new(0x2601, 0x0600, 0x9280, 0x6B50, 0x595C, 0x721F, 0xB469, 0xE80E)
        );
    }

    #[test]
    fn socket_line_established_v4() {
        let line = "   3: 0100007F:9D5D 0100007F:0277 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0";
        let ((local, remote), row) = parse_socket_line(line).expect("row");
        assert_eq!(
            local,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0x9D5D)
        );
        assert_eq!(
            remote,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0x0277)
        );
        assert_eq!(row.inode, 12345);
        assert_eq!(row.uid, 1000);
    }

    #[test]
    fn socket_line_ignores_non_established() {
        // State 0A = LISTEN.
        let line = "   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 8105 1 0000000000000000 100 0 0 10 0";
        assert!(parse_socket_line(line).is_none());
    }

    #[test]
    fn parse_socket_table_populates_map() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                    0: 0100007F:9D5D 0100007F:0277 01 00000000:00000000 00:00000000 00000000  1000        0 42 1 0000000000000000 100 0 0 10 0\n\
                    1: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 8105 1 0000000000000000 100 0 0 10 0\n";
        let mut map = HashMap::new();
        parse_socket_table(text, &mut map);
        assert_eq!(map.len(), 1);
        let row = map.values().next().unwrap();
        assert_eq!(row.inode, 42);
    }

    #[test]
    fn socket_inode_link_parse() {
        assert_eq!(
            socket_inode_from_link(Path::new("socket:[12345]")),
            Some(12345)
        );
        assert_eq!(socket_inode_from_link(Path::new("pipe:[7]")), None);
    }

    #[test]
    fn resolver_returns_unknown_when_root_empty() {
        let tmp = tempdir();
        let mut r = LinuxProcResolver::with_root(&tmp);
        let a = "127.0.0.1:1234".parse().unwrap();
        let b = "127.0.0.1:5678".parse().unwrap();
        assert_eq!(r.resolve(a, b), Origin::Unknown);
    }

    #[test]
    fn resolver_finds_local_process_via_fake_proc_tree() {
        let tmp = tempdir();
        // /proc/net/tcp with one established row: 127.0.0.1:0x1234 -> 127.0.0.1:0x5678
        // inode 99, uid 1000.
        let tcp = "  sl  local_address rem_address   st\n\
                   0: 0100007F:1234 0100007F:5678 01 00000000:00000000 00:00000000 00000000  1000        0 99 1 0 100 0 0 10 0\n";
        fs::create_dir_all(tmp.join("proc/net")).unwrap();
        fs::write(tmp.join("proc/net/tcp"), tcp).unwrap();

        // /proc/4242/{comm,cmdline,status,fd/3 -> socket:[99]}
        let pid_dir = tmp.join("proc/4242");
        fs::create_dir_all(pid_dir.join("fd")).unwrap();
        fs::write(pid_dir.join("comm"), "curl\n").unwrap();
        fs::write(pid_dir.join("cmdline"), b"curl\0https://example.com\0").unwrap();
        fs::write(
            pid_dir.join("status"),
            "Name:\tcurl\nUid:\t1000\t1000\t1000\t1000\n",
        )
        .unwrap();
        std::os::unix::fs::symlink("socket:[99]", pid_dir.join("fd/3")).unwrap();

        let mut r = LinuxProcResolver::with_root(&tmp);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0x1234);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0x5678);
        match r.resolve(local, remote) {
            Origin::Local(p) => {
                assert_eq!(p.pid, 4242);
                assert_eq!(p.comm, "curl");
                assert_eq!(p.cmdline, "curl https://example.com");
                assert_eq!(p.uid, 1000);
            }
            other => panic!("expected Local, got {other:?}"),
        }
        // Reversed order should also resolve (socket table only stores one
        // direction; resolver tries both).
        assert!(matches!(r.resolve(remote, local), Origin::Local(_)));
    }

    #[test]
    fn resolver_reports_other_user_when_fd_unreadable() {
        let tmp = tempdir();
        let tcp = "  sl  local_address rem_address   st\n\
                   0: 0100007F:1234 0100007F:5678 01 00000000:00000000 00:00000000 00000000  0        0 77 1 0 100 0 0 10 0\n";
        fs::create_dir_all(tmp.join("proc/net")).unwrap();
        fs::write(tmp.join("proc/net/tcp"), tcp).unwrap();
        // No matching /proc/<pid>/fd link → we cannot find the process.
        let mut r = LinuxProcResolver::with_root(&tmp);
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0x1234);
        let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0x5678);
        assert_eq!(r.resolve(a, b), Origin::OtherUser { uid: 0 });
    }

    /// Create a unique temporary directory. Using `std` only — avoids
    /// pulling in `tempfile` just for a couple of tests.
    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "seehandshake-origin-{}-{}-{}",
            std::process::id(),
            n,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
