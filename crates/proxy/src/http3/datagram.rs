//! HTTP Datagram routing for downstream HTTP/3 streams.

use std::{collections::HashMap, sync::Arc};

use bytes::Bytes;
use h3::quic::StreamId;
use h3_datagram::datagram_handler::{DatagramReader, DatagramSender};
use h3_quinn::datagram::{RecvDatagramHandler, SendDatagramHandler};
use tokio::sync::{Mutex, mpsc};

pub(super) type RoutedDatagram = Result<Bytes, String>;

pub(super) struct DatagramRelay {
    pub(super) reader: mpsc::Receiver<RoutedDatagram>,
    pub(super) sender: DatagramSender<SendDatagramHandler, Bytes>,
}

#[derive(Clone)]
pub(super) struct DatagramRouter {
    routes: Arc<Mutex<HashMap<StreamId, mpsc::Sender<RoutedDatagram>>>>,
}

pub(super) struct DatagramRouterState {
    pub(super) router: DatagramRouter,
    pub(super) task: tokio::task::JoinHandle<()>,
}

impl DatagramRouter {
    pub(super) fn start(mut reader: DatagramReader<RecvDatagramHandler>) -> DatagramRouterState {
        let routes: Arc<Mutex<HashMap<StreamId, mpsc::Sender<RoutedDatagram>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let task_routes = routes.clone();

        let task = tokio::spawn(async move {
            loop {
                let datagram = match reader.read_datagram().await {
                    Ok(datagram) => datagram,
                    Err(error) => {
                        let senders = {
                            let mut routes = task_routes.lock().await;
                            routes.drain().map(|(_, sender)| sender).collect::<Vec<_>>()
                        };
                        let message = format!("downstream HTTP Datagram failed: {error}");
                        for sender in senders {
                            let _ = sender.send(Err(message.clone())).await;
                        }
                        break;
                    }
                };
                let stream_id = datagram.stream_id();
                let payload = datagram.into_payload();
                let sender = task_routes.lock().await.get(&stream_id).cloned();
                let Some(sender) = sender else {
                    continue;
                };

                if sender.send(Ok(payload)).await.is_err() {
                    task_routes.lock().await.remove(&stream_id);
                }
            }
        });

        DatagramRouterState {
            router: Self { routes },
            task,
        }
    }

    pub(super) async fn register(&self, stream_id: StreamId) -> mpsc::Receiver<RoutedDatagram> {
        let (sender, receiver) = mpsc::channel(64);
        self.routes.lock().await.insert(stream_id, sender);
        receiver
    }

    pub(super) async fn unregister(&self, stream_id: StreamId) {
        self.routes.lock().await.remove(&stream_id);
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use bytes::Bytes;
    use h3::quic::StreamId;
    use tokio::sync::Mutex;

    use super::DatagramRouter;

    fn stream(value: u64) -> StreamId {
        StreamId::try_from(value).expect("stream id")
    }

    fn router() -> DatagramRouter {
        DatagramRouter {
            routes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[tokio::test]
    async fn register_keeps_routes_separate_per_stream() {
        let router = router();
        let mut first = router.register(stream(0)).await;
        let mut second = router.register(stream(4)).await;

        let sender = router
            .routes
            .lock()
            .await
            .get(&stream(0))
            .cloned()
            .expect("route for stream 0");

        sender
            .send(Ok(Bytes::from_static(b"payload")))
            .await
            .expect("payload delivers");

        assert_eq!(first.recv().await, Some(Ok(Bytes::from_static(b"payload"))));
        assert!(second.try_recv().is_err(), "stream 4 receives no payload");
    }

    #[tokio::test]
    async fn unregister_drops_the_route() {
        let router = router();
        let receiver = router.register(stream(0)).await;

        let sender = router
            .routes
            .lock()
            .await
            .get(&stream(0))
            .cloned()
            .expect("route registered");

        router.unregister(stream(0)).await;

        assert!(
            router.routes.lock().await.get(&stream(0)).is_none(),
            "route is removed"
        );

        drop(receiver);

        assert!(
            sender
                .send(Ok(Bytes::from_static(b"payload")))
                .await
                .is_err(),
            "the dropped route receiver closes the channel"
        );
    }

    #[tokio::test]
    async fn reregister_replaces_the_previous_route() {
        let router = router();
        let mut first = router.register(stream(0)).await;
        let _second = router.register(stream(0)).await;

        assert!(
            first.recv().await.is_none(),
            "the replaced route receiver closes"
        );
    }
}
