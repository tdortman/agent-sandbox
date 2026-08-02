//! QUIC Transport traits
//!
//! This module includes traits and types meant to allow being generic over any
//! QUIC implementation.

use crate::datagram::EncodedDatagram;
use bytes::Buf;
use core::task;
use h3::quic::ConnectionErrorIncoming;
use std::task::Poll;

/// Connection extension trait for datagram handlers.
pub trait DatagramConnectionExt<B: Buf> {
    /// The type of the datagram send handler.
    type SendDatagramHandler: SendDatagram<B>;

    /// The type of the datagram receive handler.
    type RecvDatagramHandler: RecvDatagram;

    /// Gets the send datagram handler.
    fn send_datagram_handler(&self) -> Self::SendDatagramHandler;

    /// Gets the receive datagram handler.
    fn recv_datagram_handler(&self) -> Self::RecvDatagramHandler;
}

/// Extends the connection trait for sending datagrams.
pub trait SendDatagram<B: Buf> {
    /// Sends a datagram.
    fn send_datagram<T: Into<EncodedDatagram<B>>>(
        &mut self,
        data: T,
    ) -> Result<(), SendDatagramErrorIncoming>;
}

/// Extends the connection trait for receiving datagrams.
pub trait RecvDatagram {
    /// The buffer type.
    type Buffer: Buf;

    /// Polls the connection for incoming datagrams.
    fn poll_incoming_datagram(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::Buffer, ConnectionErrorIncoming>>;
}

/// Types of errors when sending datagrams.
#[derive(Debug)]
pub enum SendDatagramErrorIncoming {
    /// The peer does not accept datagrams.
    NotAvailable,
    /// The datagram is too large.
    TooLarge,
    /// The connection reports an error.
    ConnectionError(ConnectionErrorIncoming),
}
