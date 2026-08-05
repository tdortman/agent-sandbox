//! Transparent UDP socket for the HTTP/3 backend.
//!
//! The socket reads kernel original-destination metadata for every datagram
//! so the proxy can attribute intercepted QUIC associations to their real
//! origin. Outbound datagrams carry an explicit source address so replies
//! appear to come from the original destination.
//!
//! Quinn drives the socket through its [`quinn::AsyncUdpSocket`] seam, which
//! keeps the packet loop project-owned while the endpoint handles QUIC
//! connections, routing, and timers.

use nix::sys::socket::{
    ControlMessage, ControlMessageOwned, recvmsg, sendmsg, setsockopt, sockopt,
};

use rama_net::socket::core::{Domain, Protocol, Socket as Socket2, Type};

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::AsRawFd,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::io::unix::AsyncFd;

/// One received UDP datagram and its metadata.
type ReceivedDatagram = (usize, Option<SocketAddr>, Option<IpAddr>);

/// One project-owned transparent UDP socket.
///
/// `transparent` selects whether datagrams may carry a non-local source
/// address on send and whether the received original destination is used as
/// the connection's local address. Non-transparent sockets (the unprivileged
/// test harness) report their own bound address instead.
#[derive(Debug)]
pub struct TransparentUdpSocket {
    inner: Arc<AsyncFd<std::net::UdpSocket>>,
    bound: SocketAddr,
    transparent: bool,
}

impl TransparentUdpSocket {
    /// Bind a non-blocking UDP socket with the requested options.
    ///
    /// # Errors
    ///
    /// Returns an error when the socket cannot be created, configured, or
    /// bound.
    pub fn bind(address: SocketAddr, transparent: bool) -> io::Result<Self> {
        let domain = if address.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket2::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;

        if address.is_ipv6() {
            socket.set_ip_transparent_v6(transparent)?;
            socket.set_only_v6(true)?;
            setsockopt(&socket, sockopt::Ipv6RecvPacketInfo, &transparent)?;
            setsockopt(&socket, sockopt::Ipv6OrigDstAddr, &transparent)?;
        } else {
            socket.set_ip_transparent_v4(transparent)?;
            setsockopt(&socket, sockopt::Ipv4PacketInfo, &transparent)?;
            setsockopt(&socket, sockopt::Ipv4OrigDstAddr, &transparent)?;
        }

        socket.bind(&address.into())?;
        socket.set_nonblocking(true)?;
        let socket: std::net::UdpSocket = socket.into();
        let inner = Arc::new(AsyncFd::new(socket)?);

        Ok(Self {
            inner,
            bound: address,
            transparent,
        })
    }

    fn recv_one(&self, buffer: &mut [u8]) -> io::Result<Option<ReceivedDatagram>> {
        let mut iov = [std::io::IoSliceMut::new(buffer)];
        let mut cmsg_buffer = [0u8; 128];

        let message = recvmsg::<nix::sys::socket::SockaddrStorage>(
            self.inner.get_ref().as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_buffer),
            nix::sys::socket::MsgFlags::MSG_DONTWAIT,
        );

        let message = match message {
            Ok(message) => message,
            Err(nix::errno::Errno::EAGAIN) => return Ok(None),
            Err(error) => return Err(io::Error::from(error)),
        };

        let source = message.address.as_ref().and_then(|address| {
            address
                .as_sockaddr_in()
                .copied()
                .map(SocketAddr::from)
                .or_else(|| address.as_sockaddr_in6().copied().map(SocketAddr::from))
        });

        let mut original_destination = None;
        let mut packet_destination = None;

        if let Ok(cmsgs) = message.cmsgs() {
            for cmsg in cmsgs {
                match cmsg {
                    ControlMessageOwned::Ipv4OrigDstAddr(address) => {
                        original_destination = Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                            address.sin_addr.s_addr,
                        ))));
                    }

                    ControlMessageOwned::Ipv6OrigDstAddr(address) => {
                        original_destination =
                            Some(IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)));
                    }

                    ControlMessageOwned::Ipv4PacketInfo(info) => {
                        packet_destination = Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                            info.ipi_addr.s_addr,
                        ))));
                    }

                    ControlMessageOwned::Ipv6PacketInfo(info) => {
                        packet_destination =
                            Some(IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)));
                    }

                    _ => {}
                }
            }
        }

        let original_destination = original_destination.or(packet_destination);
        Ok(Some((message.bytes, source, original_destination)))
    }

    fn send_one(
        &self,
        buffer: &[u8],
        destination: SocketAddr,
        source: Option<IpAddr>,
    ) -> io::Result<()> {
        let result = match (self.bound.is_ipv4(), source) {
            (true, Some(IpAddr::V4(source))) => {
                let packet_info = nix::libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: nix::libc::in_addr {
                        s_addr: u32::from_ne_bytes(source.octets()),
                    },
                    ipi_addr: nix::libc::in_addr { s_addr: 0 },
                };

                sendmsg(
                    self.inner.get_ref().as_raw_fd(),
                    &[std::io::IoSlice::new(buffer)],
                    &[ControlMessage::Ipv4PacketInfo(&packet_info)],
                    nix::sys::socket::MsgFlags::MSG_DONTWAIT,
                    Some(&nix::sys::socket::SockaddrStorage::from(destination)),
                )
            }
            (false, Some(IpAddr::V6(source))) => {
                let packet_info = nix::libc::in6_pktinfo {
                    ipi6_ifindex: 0,
                    ipi6_addr: nix::libc::in6_addr {
                        s6_addr: source.octets(),
                    },
                };

                sendmsg(
                    self.inner.get_ref().as_raw_fd(),
                    &[std::io::IoSlice::new(buffer)],
                    &[ControlMessage::Ipv6PacketInfo(&packet_info)],
                    nix::sys::socket::MsgFlags::MSG_DONTWAIT,
                    Some(&nix::sys::socket::SockaddrStorage::from(destination)),
                )
            }
            _ => sendmsg(
                self.inner.get_ref().as_raw_fd(),
                &[std::io::IoSlice::new(buffer)],
                &[],
                nix::sys::socket::MsgFlags::MSG_DONTWAIT,
                Some(&nix::sys::socket::SockaddrStorage::from(destination)),
            ),
        };

        match result {
            Ok(_) => Ok(()),
            Err(nix::errno::Errno::EAGAIN) => Err(io::ErrorKind::WouldBlock.into()),
            Err(error) => Err(io::Error::from(error)),
        }
    }
}

/// Readiness poller handed to quinn for send retries.
#[derive(Debug)]
struct TransparentUdpPoller {
    inner: Arc<AsyncFd<std::net::UdpSocket>>,
}

impl quinn::UdpPoller for TransparentUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner
            .poll_write_ready(cx)
            .map(|result| result.map(|_| ()))
    }
}

impl quinn::AsyncUdpSocket for TransparentUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(TransparentUdpPoller {
            inner: Arc::clone(&self.inner),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        let source = if self.transparent {
            transmit.src_ip
        } else {
            None
        };

        self.send_one(transmit.contents, transmit.destination, source)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        metas: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some(buffer) = bufs.first_mut() else {
            return Poll::Ready(Ok(0));
        };

        let Some(meta) = metas.first_mut() else {
            return Poll::Ready(Err(io::Error::other(
                "quinn supplied no receive metadata slot",
            )));
        };

        loop {
            let mut guard = match self.inner.poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            };

            match self.recv_one(buffer) {
                Ok(Some((length, source, original_destination))) => {
                    let destination = if self.transparent {
                        original_destination.ok_or_else(|| {
                            io::Error::other(
                                "transparent UDP datagram arrived without original destination",
                            )
                        })?
                    } else {
                        original_destination.unwrap_or_else(|| {
                            if self.bound.is_ipv4() {
                                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                            } else {
                                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                            }
                        })
                    };

                    meta.addr = source.ok_or_else(|| {
                        io::Error::other("UDP datagram arrived without a source address")
                    })?;
                    meta.len = length;
                    meta.stride = length;
                    meta.ecn = None;
                    meta.dst_ip = Some(destination);

                    return Poll::Ready(Ok(1));
                }

                Ok(None) => {
                    guard.clear_ready();
                }

                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                }

                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.bound)
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        false
    }
}
