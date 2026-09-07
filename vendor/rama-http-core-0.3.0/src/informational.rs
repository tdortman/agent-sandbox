//! Bounded interim response delivery from a service to its HTTP connection.
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use rama_core::extensions::Extension;
use rama_http_types::{Response, StatusCode};

#[derive(Debug, Default)]
struct State {
    queue: VecDeque<Response<()>>,
    count: usize,
    closed: bool,
    waker: Option<Waker>,
}

/// Request extension for sending at most 16 interim responses before the final
/// head.
#[derive(Clone, Debug, Extension)]
#[extension(tags(http))]
pub struct InformationalSender(Arc<Mutex<State>>, bool);

impl InformationalSender {
    pub(crate) fn new(local_continue: bool) -> Self {
        Self(Arc::new(Mutex::new(State::default())), local_continue)
    }

    /// Queue an informational head. Invalid status codes and framing are
    /// rejected. Local HTTP/1 Continue responses are counted but not
    /// duplicated.
    ///
    /// # Errors
    /// Fails for invalid heads, more than 16 heads, or a completed response.
    pub fn send(&self, response: Response<()>) -> crate::Result<()> {
        let invalid = !response.status().is_informational()
            || response.status() == StatusCode::SWITCHING_PROTOCOLS
            || response.headers().contains_key("content-length")
            || response.headers().contains_key("transfer-encoding");
        let mut state = self.0.lock().expect("informational lock");
        if invalid {
            state.count = 17;
            if let Some(waker) = state.waker.take() {
                waker.wake();
            }
            return Err(crate::Error::new_user_unsupported_status_code()
                .with_display("invalid or excessive informational response"));
        }
        if state.closed {
            return Err(crate::Error::new_user_unsupported_status_code()
                .with_display("invalid or excessive informational response"));
        }
        state.count = state.count.saturating_add(1);
        if state.count <= 16 && !(self.1 && response.status() == StatusCode::CONTINUE) {
            state.queue.push_back(response);
        }
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
        if state.count > 16 {
            return Err(crate::Error::new_user_unsupported_status_code()
                .with_display("invalid or excessive informational response"));
        }
        Ok(())
    }

    pub(crate) fn poll(&self, cx: &mut Context<'_>) -> Poll<crate::Result<Response<()>>> {
        let mut state = self.0.lock().expect("informational lock");
        if state.count > 16 {
            return Poll::Ready(Err(crate::Error::new_user_unsupported_status_code()
                .with_display("invalid or excessive informational response")));
        }
        if let Some(head) = state.queue.pop_front() {
            return Poll::Ready(Ok(head));
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    pub(crate) fn close(&self) {
        self.0.lock().expect("informational lock").closed = true;
    }
}
