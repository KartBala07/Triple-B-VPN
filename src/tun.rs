//! macOS utun (layer-3 tunnel) device handling.
//!
//! Creating a utun requires root: PF_SYSTEM socket + CTLIOCGINFO + connect on
//! the com.apple.net.utun_control kernel control. Packets are prefixed with a
//! 4-byte address-family header in network byte order on both read and write.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd};

const PF_SYSTEM: i32 = 32;
const SOCK_DGRAM: i32 = 2;
const SYSPROTO_CONTROL: i32 = 2;
const AF_SYS_CONTROL: u8 = 2;
const CTLIOCGINFO: u64 = 0xc064_4e03;
const UTUN_OPT_IFNAME: i32 = 2;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 30;
const POLLIN: i16 = 0x0001;

#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

extern "C" {
    fn socket(domain: i32, ty: i32, proto: i32) -> i32;
    fn ioctl(fd: i32, request: u64, ...) -> i32;
    fn connect(fd: i32, addr: *const u8, len: u32) -> i32;
    fn getsockopt(fd: i32, level: i32, optname: i32, optval: *mut u8, optlen: *mut u32) -> i32;
    fn close(fd: i32) -> i32;
    fn poll(fds: *mut PollFd, nfds: u32, timeout: i32) -> i32;
}

pub struct Tun {
    file: File,
    pub name: String,
}

impl Tun {
    pub fn create(unit: u32) -> io::Result<Tun> {
        unsafe {
            let fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut info = CtlInfo { ctl_id: 0, ctl_name: [0u8; 96] };
            let cname = b"com.apple.net.utun_control";
            info.ctl_name[..cname.len()].copy_from_slice(cname);
            if ioctl(fd, CTLIOCGINFO, &mut info as *mut CtlInfo) < 0 {
                let e = io::Error::last_os_error();
                close(fd);
                return Err(e);
            }
            let sc = SockaddrCtl {
                sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
                sc_family: AF_SYS_CONTROL,
                ss_sysaddr: AF_SYS_CONTROL as u16,
                sc_id: info.ctl_id,
                sc_unit: unit,
                sc_reserved: [0; 5],
            };
            let r = connect(
                fd,
                &sc as *const SockaddrCtl as *const u8,
                std::mem::size_of::<SockaddrCtl>() as u32,
            );
            if r < 0 {
                let e = io::Error::last_os_error();
                close(fd);
                return Err(e);
            }
            let mut namebuf = [0u8; 64];
            let mut len = namebuf.len() as u32;
            if getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                namebuf.as_mut_ptr(),
                &mut len,
            ) < 0
            {
                let e = io::Error::last_os_error();
                close(fd);
                return Err(e);
            }
            let end = namebuf.iter().position(|&c| c == 0).unwrap_or(namebuf.len());
            let name = String::from_utf8_lossy(&namebuf[..end]).to_string();
            Ok(Tun { file: File::from_raw_fd(fd), name })
        }
    }

    pub fn try_clone(&self) -> io::Result<Tun> {
        Ok(Tun { file: self.file.try_clone()?, name: self.name.clone() })
    }

    /// Read one IP packet. Returns Ok(None) on timeout.
    pub fn recv(&mut self, out: &mut [u8], timeout_ms: i32) -> io::Result<Option<usize>> {
        let mut pfd = PollFd { fd: self.file.as_raw_fd(), events: POLLIN, revents: 0 };
        let r = unsafe { poll(&mut pfd, 1, timeout_ms) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                return Ok(None);
            }
            return Err(e);
        }
        if r == 0 {
            return Ok(None);
        }
        let mut buf = vec![0u8; 4 + 65536];
        let n = self.file.read(&mut buf)?;
        if n <= 4 {
            return Ok(Some(0));
        }
        let plen = n - 4;
        if out.len() < plen {
            return Ok(Some(0));
        }
        out[..plen].copy_from_slice(&buf[4..4 + plen]);
        Ok(Some(plen))
    }

    /// Inject one IP packet into the network stack.
    pub fn send(&mut self, pkt: &[u8]) -> io::Result<()> {
        if pkt.is_empty() {
            return Ok(());
        }
        let family = match pkt[0] >> 4 {
            4 => AF_INET,
            6 => AF_INET6,
            _ => return Ok(()),
        };
        let mut buf = Vec::with_capacity(4 + pkt.len());
        buf.extend_from_slice(&family.to_be_bytes());
        buf.extend_from_slice(pkt);
        self.file.write_all(&buf)
    }
}
