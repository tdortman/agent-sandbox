use std::os::unix::io::AsRawFd;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub(crate) const CLIENT_PEEK_BYTES: usize = 16 * 1024;
pub(crate) const CLIENT_PEEK_TIMEOUT: Duration = Duration::from_secs(5);

#[allow(unsafe_code)]
pub(crate) fn original_dst(stream: &TcpStream) -> Option<(String, u16)> {
    let mut raw = [0_u8; 16];
    let mut len = libc::socklen_t::try_from(std::mem::size_of_val(&raw)).unwrap_or(16);
    let fd = stream.as_raw_fd();
    // SAFETY: `getsockopt` with `SO_ORIGINAL_DST` on an IPv4 TCP socket.
    let ok = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_IP,
            80,
            raw.as_mut_ptr().cast(),
            std::ptr::addr_of_mut!(len),
        )
    };
    if ok != 0 || len < 8 {
        return None;
    }
    let port = u16::from_be_bytes([raw[2], raw[3]]);
    let ip = std::net::Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7]);
    Some((ip.to_string(), port))
}

pub(crate) async fn read_client_peek(stream: &TcpStream) -> Vec<u8> {
    let mut buf = vec![0_u8; CLIENT_PEEK_BYTES];
    match tokio::time::timeout(CLIENT_PEEK_TIMEOUT, stream.peek(&mut buf)).await {
        Ok(Ok(n)) => buf[..n].to_vec(),
        _ => Vec::new(),
    }
}

pub(crate) async fn pipe_bidirectional(
    mut client: TcpStream,
    mut remote: TcpStream,
    client_prefix: Vec<u8>,
) {
    let (mut cr, mut cw) = client.split();
    let (mut rr, mut rw) = remote.split();
    let c2r = async {
        if !client_prefix.is_empty() {
            let _ = rw.write_all(&client_prefix).await;
        }
        let _ = tokio::io::copy(&mut cr, &mut rw).await;
        let _ = rw.shutdown().await;
    };
    let r2c = async {
        let _ = tokio::io::copy(&mut rr, &mut cw).await;
        let _ = cw.shutdown().await;
    };
    let _ = tokio::join!(c2r, r2c);
}
