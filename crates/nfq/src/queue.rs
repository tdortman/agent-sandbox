//! NFQUEUE binding, copy range, the streaming packet scheduler, and the
//! systemd readiness marker.

use std::{
    collections::VecDeque,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use agent_sandbox_core::{FlowProtocol, PersistentRpcClient};
use nfq_updated::{Queue, Verdict};
use tokio::{
    io::{Interest, unix::AsyncFd},
    task::JoinSet,
};

use crate::{
    flow::{NfqState, PacketOutcome, apply_verdict_mark, handle_packet},
    packet,
};

/// Number of bytes to copy from each queued packet.
/// `u16::MAX` ensures the full UDP DNS response payload is available
/// for hickory-proto parsing (CNAME chains and multi-answer responses
/// routinely exceed the standard Ethernet MTU's 1500-byte segment).
const COPY_RANGE: u16 = u16::MAX;

/// Packets read from the kernel but not yet handed to a handler. Past this
/// bound reading pauses and the kernel queue absorbs the backlog.
const MAX_PARKED: usize = 256;

/// Packets of one flow that may wait behind the flow's running handler.
/// Further packets of that flow are dropped at once, so a single flow cannot
/// fill the park and stop the reading that other flows depend on. TCP
/// retransmits and UDP senders try again.
const MAX_PARKED_PER_FLOW: usize = 4;

/// Policy clients, one per handler. A handler waiting on a policy prompt
/// occupies its client until the verdict, so the pool is sized well above
/// what one sandbox can have waiting on prompts: policyd lets one scope hold
/// at most `MAX_PROMPTS_PER_SCOPE` (16) in flight and the requests without a
/// scope `MAX_UNATTRIBUTED_PROMPTS` (8), and blocks the rest at once.
const HANDLERS: usize = 64;

pub fn open_queue(queue_num: u16, queue_len: u32) -> std::io::Result<Queue> {
    let mut queue = Queue::open()?;
    queue.bind(queue_num)?;
    queue.set_fail_open(queue_num, false)?;
    queue.set_recv_gso(queue_num, false)?;
    queue.set_copy_range(queue_num, COPY_RANGE)?;
    queue.set_queue_max_len(queue_num, queue_len)?;
    Ok(queue)
}

pub struct ReadyMarker(PathBuf);

/// Identity of one transport flow; packets sharing it are handled in order.
#[derive(Clone, Copy, PartialEq, Eq)]
struct FlowKey {
    protocol: FlowProtocol,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
}

/// Scheduling constraints of one queued packet.
struct Order {
    /// `None` for unparsed packets.
    flow: Option<FlowKey>,
    /// DNS replies (`src_port == 53`) and unparsed packets.
    barrier: bool,
}

/// A packet source that also accepts verdicts; `NetlinkQueue` in production.
trait PacketQueue {
    type Packet: Send + 'static;

    fn recv(&mut self) -> impl Future<Output = std::io::Result<Self::Packet>> + Send;

    fn verdict(&mut self, packet: Self::Packet) -> std::io::Result<()>;

    fn order(packet: &Self::Packet) -> Order;

    /// Drop `packet` without handing it to a handler.
    fn drop_packet(&mut self, packet: Self::Packet) -> std::io::Result<()>;
}

struct NetlinkQueue(AsyncFd<Queue>);

impl PacketQueue for NetlinkQueue {
    type Packet = nfq_updated::Message;

    async fn recv(&mut self) -> std::io::Result<Self::Packet> {
        self.0.async_io_mut(Interest::READABLE, Queue::recv).await
    }

    fn verdict(&mut self, packet: Self::Packet) -> std::io::Result<()> {
        self.0.get_mut().verdict(packet)
    }

    fn drop_packet(&mut self, mut packet: Self::Packet) -> std::io::Result<()> {
        packet.set_verdict(Verdict::Drop);
        self.verdict(packet)
    }

    fn order(packet: &Self::Packet) -> Order {
        let meta = packet::parse_ipv4(packet.get_payload())
            .or_else(|| packet::parse_ipv6(packet.get_payload()));

        Order {
            flow: meta.map(|meta| FlowKey {
                protocol: meta.protocol,
                src_ip: meta.src_ip,
                src_port: meta.src_port,
                dst_ip: meta.dst_ip,
                dst_port: meta.dst_port,
            }),
            barrier: meta.is_none_or(|meta| meta.src_port == 53),
        }
    }
}

struct Parked<P> {
    packet: P,
    order: Order,
}

struct Finished<P, C> {
    packet: P,
    client: C,
    order: Order,
}

/// Dispatch state: at most one handler per client runs at a time, and a
/// handler blocked on a policy prompt occupies only its own client.
struct Scheduler<P, C> {
    clients: Vec<C>,
    running: JoinSet<Finished<P, C>>,
    running_flows: Vec<FlowKey>,
    barrier_running: bool,
    parked: VecDeque<Parked<P>>,
}

impl<P: Send + 'static, C: Send + 'static> Scheduler<P, C> {
    /// Start every parked packet that may run now, in arrival order.
    ///
    /// Ordering guarantees:
    /// - Packets of one flow start in arrival order and never overlap, so their
    ///   verdicts are issued in arrival order. A packet whose flow is busy
    ///   stays parked without holding back other flows.
    /// - A barrier starts after every earlier packet that was not itself parked
    ///   behind a busy flow, and no later packet starts until it finishes.
    ///   Later packets therefore always see its effects (DNS mappings,
    ///   verdict-cache invalidation). It does not wait for earlier handlers to
    ///   finish, because one of them may be blocked on an approval prompt for
    ///   minutes, which would stall every other sandbox; earlier parked packets
    ///   are in that same blocked-flow situation, so the barrier passes them
    ///   too.
    fn dispatch<H>(&mut self, handle: &H)
    where
        H: Fn(&mut C, P) -> P + Clone + Send + 'static,
    {
        let mut skipped: Vec<FlowKey> = Vec::new();
        let mut index = 0;

        while !self.barrier_running && !self.clients.is_empty() && index < self.parked.len() {
            let order = &self.parked[index].order;
            let busy = order
                .flow
                .filter(|flow| self.running_flows.contains(flow) || skipped.contains(flow));

            if let Some(flow) = busy {
                if order.barrier {
                    break;
                }
                skipped.push(flow);
                index += 1;
                continue;
            }

            let parked = self.parked.remove(index).expect("index is in bounds");
            let mut client = self.clients.pop().expect("checked non-empty");
            self.running_flows.extend(parked.order.flow);
            self.barrier_running = parked.order.barrier;
            let handle = handle.clone();

            self.running.spawn_blocking(move || {
                let packet = handle(&mut client, parked.packet);
                Finished {
                    packet,
                    client,
                    order: parked.order,
                }
            });
        }
    }

    /// Packets of `flow` waiting for a handler.
    fn parked_in(&self, flow: FlowKey) -> usize {
        self.parked
            .iter()
            .filter(|parked| parked.order.flow == Some(flow))
            .count()
    }

    /// Return the finished handler's client and flow, yielding the packet to
    /// verdict.
    fn finish(&mut self, finished: Finished<P, C>) -> P {
        self.clients.push(finished.client);

        if let Some(flow) = finished.order.flow
            && let Some(position) = self.running_flows.iter().position(|key| *key == flow)
        {
            self.running_flows.swap_remove(position);
        }
        if finished.order.barrier {
            self.barrier_running = false;
        }

        finished.packet
    }
}

/// Read packets while handlers run and issue each verdict the moment its
/// handler finishes. One handler runs per entry in `clients`.
async fn schedule<Q, C, H>(queue: &mut Q, clients: Vec<C>, handle: H) -> std::io::Result<()>
where
    Q: PacketQueue + Send,
    C: Send + 'static,
    H: Fn(&mut C, Q::Packet) -> Q::Packet + Clone + Send + Sync + 'static,
{
    let mut scheduler = Scheduler {
        clients,
        running: JoinSet::new(),
        running_flows: Vec::new(),
        barrier_running: false,
        parked: VecDeque::new(),
    };

    loop {
        scheduler.dispatch(&handle);

        // With nothing parked past the bound, every client is free or a
        // handler is running, so at least one branch is always enabled.
        tokio::select! {
            received = queue.recv(), if scheduler.parked.len() < MAX_PARKED => match received {
                Ok(packet) => {
                    let order = Q::order(&packet);

                    if !order.barrier
                        && order
                            .flow
                            .is_some_and(|flow| scheduler.parked_in(flow) >= MAX_PARKED_PER_FLOW)
                    {
                        if let Err(error) = queue.drop_packet(packet) {
                            tracing::warn!(%error, "nfqueue verdict error");
                        }
                    } else {
                        scheduler.parked.push_back(Parked { packet, order });
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "nfqueue recv error");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            },
            Some(joined) = scheduler.running.join_next() => {
                let finished = joined.map_err(std::io::Error::other)?;
                let packet = scheduler.finish(finished);

                if let Err(error) = queue.verdict(packet) {
                    tracing::warn!(%error, "nfqueue verdict error");
                }
            }
        }
    }
}

/// Run bounded independent-flow checks without blocking the async I/O driver.
pub async fn run_queue(
    mut queue: Queue,
    state: NfqState,
    policy_socket: String,
    timeout: Duration,
) -> std::io::Result<()> {
    queue.set_nonblocking(true);
    // SAFETY: `Queue` owns its netlink socket, which stays open until the
    // `AsyncFd` owning the queue is dropped.
    #[allow(unsafe_code, reason = "AsyncFd registration is unsafe")]
    let queue = unsafe { AsyncFd::register(queue) }?;
    let state = Arc::new(state);

    let clients: Vec<_> = (0..HANDLERS)
        .map(|_| PersistentRpcClient::new(policy_socket.clone()))
        .collect();
    let runtime = tokio::runtime::Handle::current();

    schedule(
        &mut NetlinkQueue(queue),
        clients,
        move |client: &mut PersistentRpcClient, mut message: nfq_updated::Message| {
            let PacketOutcome { verdict, meta } =
                handle_packet(&state, client, timeout, &message, &runtime);

            apply_verdict_mark(&state, &mut message, verdict, meta);
            message.set_verdict(verdict);
            message
        },
    )
    .await
}

impl Drop for ReadyMarker {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn validate_invocation_id(value: &str) -> std::io::Result<()> {
    if value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "INVOCATION_ID must be exactly 32 lowercase hexadecimal characters",
    ))
}

pub fn write_ready_marker_or_exit(path: &Path) -> ReadyMarker {
    match write_ready_marker(path) {
        Ok(marker) => marker,

        Err(err) => {
            eprintln!(
                "agent-sandbox-nfq: failed to write readiness marker {}: {err}",
                path.display()
            );
            std::process::exit(1);
        }
    }
}

fn write_ready_marker(path: &Path) -> std::io::Result<ReadyMarker> {
    let invocation_id = std::env::var("INVOCATION_ID").map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "INVOCATION_ID is required when --ready-file is configured",
        )
    })?;

    validate_invocation_id(&invocation_id)?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&temporary, invocation_id.as_bytes())?;
    let mut permissions = std::fs::metadata(&temporary)?.permissions();

    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o644);
    }

    if let Err(error) = std::fs::set_permissions(&temporary, permissions)
        .and_then(|()| std::fs::rename(&temporary, path))
    {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }

    Ok(ReadyMarker(path.to_path_buf()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_marker_requires_lowercase_32_hex_invocation_id() {
        assert!(validate_invocation_id("0123456789abcdef0123456789abcdef").is_ok());
        assert!(validate_invocation_id("0123456789ABCDEF0123456789abcdef").is_err());
        assert!(validate_invocation_id("0123456789abcdef").is_err());
        assert!(validate_invocation_id("0123456789abcdef0123456789abcdeg").is_err());
    }
}

#[cfg(test)]
mod scheduler_tests {
    use std::{
        net::Ipv4Addr,
        sync::{Mutex, mpsc},
    };

    use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

    use super::*;

    const DNS_PORT: u16 = 53;

    /// Dropping this sender releases the handler of a blocked packet.
    type Release = mpsc::Sender<()>;

    struct TestPacket {
        id: u32,
        src_port: u16,
        gate: Option<Arc<Mutex<mpsc::Receiver<()>>>>,
    }

    struct BlockedPacket {
        packet: TestPacket,
        release: Release,
    }

    impl TestPacket {
        fn new(id: u32, src_port: u16) -> Self {
            Self {
                id,
                src_port,
                gate: None,
            }
        }

        /// A packet whose handler waits until `release` is dropped.
        fn blocked(id: u32, src_port: u16) -> BlockedPacket {
            let (release, receiver) = mpsc::channel();
            BlockedPacket {
                packet: Self {
                    gate: Some(Arc::new(Mutex::new(receiver))),
                    ..Self::new(id, src_port)
                },
                release,
            }
        }
    }

    struct TestQueue {
        packets: UnboundedReceiver<TestPacket>,
        verdicts: UnboundedSender<u32>,
        dropped: UnboundedSender<u32>,
    }

    impl PacketQueue for TestQueue {
        type Packet = TestPacket;

        async fn recv(&mut self) -> std::io::Result<TestPacket> {
            match self.packets.recv().await {
                Some(packet) => Ok(packet),
                None => std::future::pending().await,
            }
        }

        fn verdict(&mut self, packet: TestPacket) -> std::io::Result<()> {
            self.verdicts.send(packet.id).map_err(std::io::Error::other)
        }

        fn drop_packet(&mut self, packet: TestPacket) -> std::io::Result<()> {
            self.dropped.send(packet.id).map_err(std::io::Error::other)
        }

        fn order(packet: &TestPacket) -> Order {
            Order {
                flow: Some(FlowKey {
                    protocol: FlowProtocol::Udp,
                    src_ip: Ipv4Addr::new(10, 0, 0, 2).into(),
                    src_port: packet.src_port,
                    dst_ip: Ipv4Addr::new(192, 0, 2, 1).into(),
                    dst_port: 443,
                }),
                barrier: packet.src_port == DNS_PORT,
            }
        }
    }

    /// Runs `schedule` with three handler slots over an in-memory queue.
    struct Harness {
        packets: UnboundedSender<TestPacket>,
        verdicts: UnboundedReceiver<u32>,
        dropped: UnboundedReceiver<u32>,
        task: tokio::task::JoinHandle<std::io::Result<()>>,
    }

    impl Harness {
        fn start() -> Self {
            let (packets, packet_receiver) = unbounded_channel();
            let (verdict_sender, verdicts) = unbounded_channel();
            let (dropped_sender, dropped) = unbounded_channel();
            let mut queue = TestQueue {
                packets: packet_receiver,
                verdicts: verdict_sender,
                dropped: dropped_sender,
            };
            let task = tokio::spawn(async move {
                schedule(
                    &mut queue,
                    vec![0_usize, 1, 2],
                    |_client: &mut usize, packet: TestPacket| {
                        if let Some(gate) = &packet.gate {
                            let _ = gate.lock().expect("gate lock").recv();
                        }
                        packet
                    },
                )
                .await
            });
            Self {
                packets,
                verdicts,
                dropped,
                task,
            }
        }

        fn send(&self, packet: TestPacket) {
            self.packets.send(packet).expect("scheduler is running");
        }

        /// Sends the packet and returns the handle that unblocks it.
        fn send_blocked(&self, blocked: BlockedPacket) -> Release {
            self.send(blocked.packet);
            blocked.release
        }

        async fn next_verdict(&mut self) -> u32 {
            tokio::time::timeout(Duration::from_secs(5), self.verdicts.recv())
                .await
                .expect("verdict arrives while another flow is blocked")
                .expect("verdict channel open")
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    #[tokio::test]
    async fn unrelated_flow_gets_verdict_while_another_flow_is_blocked() {
        let mut harness = Harness::start();
        let release = harness.send_blocked(TestPacket::blocked(1, 1000));
        harness.send(TestPacket::new(2, 2000));

        assert_eq!(harness.next_verdict().await, 2);

        drop(release);
        assert_eq!(harness.next_verdict().await, 1);
    }

    #[tokio::test]
    async fn same_flow_packets_are_verdicted_in_arrival_order() {
        let mut harness = Harness::start();
        let release = harness.send_blocked(TestPacket::blocked(1, 1000));
        harness.send(TestPacket::new(2, 1000));
        harness.send(TestPacket::new(3, 2000));

        assert_eq!(harness.next_verdict().await, 3);

        drop(release);
        assert_eq!(harness.next_verdict().await, 1);
        assert_eq!(harness.next_verdict().await, 2);
    }

    #[tokio::test]
    async fn barrier_skips_blocked_flow_and_holds_back_later_packets() {
        let mut harness = Harness::start();
        let release_flow = harness.send_blocked(TestPacket::blocked(1, 1000));
        let release_barrier = harness.send_blocked(TestPacket::blocked(2, DNS_PORT));
        harness.send(TestPacket::new(3, 2000));

        // A free handler exists, yet the packet behind the blocked barrier
        // gets no verdict.
        assert!(
            tokio::time::timeout(Duration::from_millis(100), harness.verdicts.recv())
                .await
                .is_err()
        );

        drop(release_barrier);
        assert_eq!(harness.next_verdict().await, 2);
        assert_eq!(harness.next_verdict().await, 3);

        drop(release_flow);
        assert_eq!(harness.next_verdict().await, 1);
    }

    #[tokio::test]
    async fn one_flow_cannot_fill_the_park() {
        let mut harness = Harness::start();
        let release = harness.send_blocked(TestPacket::blocked(0, 1000));
        let over_cap = u32::try_from(MAX_PARKED_PER_FLOW).expect("small cap") + 1;

        for id in 1..=over_cap {
            harness.send(TestPacket::new(id, 1000));
        }
        harness.send(TestPacket::new(100, 2000));

        // The packet past the flow's cap is dropped at once; other flows are
        // still read and judged.
        let dropped = tokio::time::timeout(Duration::from_secs(5), harness.dropped.recv())
            .await
            .expect("excess packet is dropped while its flow is blocked");
        assert_eq!(dropped, Some(over_cap));
        assert_eq!(harness.next_verdict().await, 100);

        drop(release);
        assert_eq!(harness.next_verdict().await, 0);
    }

    #[tokio::test]
    async fn barrier_packets_are_never_dropped_for_their_flow() {
        let mut harness = Harness::start();
        let release = harness.send_blocked(TestPacket::blocked(0, DNS_PORT));

        for id in 1..=u32::try_from(MAX_PARKED_PER_FLOW).expect("small cap") + 2 {
            harness.send(TestPacket::new(id, DNS_PORT));
        }

        assert!(
            tokio::time::timeout(Duration::from_millis(100), harness.dropped.recv())
                .await
                .is_err()
        );
        drop(release);
    }
}
