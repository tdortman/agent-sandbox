//! Traits which define the user API for datagrams.
//! These traits are implemented for the client and server types in the `h3`
//! crate.

use crate::{
    datagram::Datagram,
    quic_traits::{DatagramConnectionExt, RecvDatagram, SendDatagram, SendDatagramErrorIncoming},
};
use bytes::Buf;
use h3::{
    error::{connection_error_creators::CloseStream, ConnectionError, StreamError},
    quic::{self, StreamId},
    ConnectionState, SharedState,
};
use std::{error::Error, fmt::Display, future::poll_fn, marker::PhantomData, sync::Arc};

/// Gives the ability to send datagrams.
#[derive(Debug)]
pub struct DatagramSender<H: SendDatagram<B>, B: Buf> {
    pub(crate) handler: H,
    pub(crate) _marker: PhantomData<B>,
    pub(crate) shared_state: Arc<SharedState>,
    pub(crate) stream_id: StreamId,
}

impl<H, B> ConnectionState for DatagramSender<H, B>
where
    H: SendDatagram<B>,
    B: Buf,
{
    fn shared_state(&self) -> &SharedState {
        self.shared_state.as_ref()
    }
}

impl<H, B> DatagramSender<H, B>
where
    H: SendDatagram<B>,
    B: Buf,
{
    /// Sends a datagram.
    pub fn send_datagram(&mut self, data: B) -> Result<(), SendDatagramError> {
        let encoded_datagram = Datagram::new(self.stream_id, data);
        match self.handler.send_datagram(encoded_datagram.encode()) {
            Ok(()) => Ok(()),
            Err(error) => Err(self.handle_send_datagram_error(error)),
        }
    }

    fn handle_send_datagram_error(
        &mut self,
        error: SendDatagramErrorIncoming,
    ) -> SendDatagramError {
        match error {
            SendDatagramErrorIncoming::NotAvailable => SendDatagramError::NotAvailable,
            SendDatagramErrorIncoming::TooLarge => SendDatagramError::TooLarge,
            SendDatagramErrorIncoming::ConnectionError(error) => {
                self.set_conn_error_and_wake(error.clone());
                SendDatagramError::ConnectionError(ConnectionError::Remote(error))
            }
        }
    }
}

#[derive(Debug)]
pub struct DatagramReader<H: RecvDatagram> {
    pub(crate) handler: H,
    pub(crate) shared_state: Arc<SharedState>,
}

impl<H> ConnectionState for DatagramReader<H>
where
    H: RecvDatagram,
{
    fn shared_state(&self) -> &SharedState {
        self.shared_state.as_ref()
    }
}

impl<H> CloseStream for DatagramReader<H> where H: RecvDatagram {}

impl<H> DatagramReader<H>
where
    H: RecvDatagram,
{
    /// Reads a datagram.
    pub async fn read_datagram(&mut self) -> Result<Datagram<H::Buffer>, StreamError> {
        match poll_fn(|cx| self.handler.poll_incoming_datagram(cx)).await {
            Ok(datagram) => Datagram::decode(datagram)
                .map_err(|error| self.handle_connection_error_on_stream(error)),
            Err(error) => Err(self.handle_quic_stream_error(
                quic::StreamErrorIncoming::ConnectionErrorIncoming {
                    connection_error: error,
                },
            )),
        }
    }
}

/// Provides the datagram API on an HTTP/3 connection.
pub trait HandleDatagramsExt<C, B>: ConnectionState
where
    B: Buf,
    C: quic::Connection<B> + DatagramConnectionExt<B>,
{
    /// Sends a datagram.
    fn get_datagram_sender(&self, stream_id: StreamId)
        -> DatagramSender<C::SendDatagramHandler, B>;

    /// Reads an incoming datagram.
    fn get_datagram_reader(&self) -> DatagramReader<C::RecvDatagramHandler>;
}

/// Types of errors when sending datagrams.
#[derive(Debug)]
#[non_exhaustive]
pub enum SendDatagramError {
    /// The peer does not accept datagrams.
    #[non_exhaustive]
    NotAvailable,
    /// The datagram is too large.
    #[non_exhaustive]
    TooLarge,
    /// The connection reports an error.
    #[non_exhaustive]
    ConnectionError(ConnectionError),
}

impl Display for SendDatagramError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAvailable => formatter.write_str("Datagrams are not available"),
            Self::TooLarge => formatter.write_str("The datagram is too large"),
            Self::ConnectionError(error) => {
                write!(formatter, "Connection error: {error}")
            }
        }
    }
}

impl Error for SendDatagramError {}
