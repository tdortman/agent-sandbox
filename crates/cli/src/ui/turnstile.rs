use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

/// A lock that hands itself to its waiters in the order they arrived.
///
/// `std::sync::Mutex` wakes whichever waiter the scheduler picks, so prompts
/// blocked behind an open dialog would appear in no particular order. Each
/// caller of [`Turnstile::wait_turn`] takes a ticket and is let through when
/// every earlier ticket has been served.
#[derive(Debug, Default)]
pub struct Turnstile {
    tickets: Mutex<Tickets>,
    changed: Condvar,
}

#[derive(Debug, Default)]
struct Tickets {
    /// The ticket the next arrival takes.
    next: u64,

    /// The ticket whose holder may proceed.
    serving: u64,
}

/// Held while a caller has its turn; the next waiter proceeds when it drops.
#[derive(Debug)]
pub struct Turn<'a> {
    turnstile: &'a Turnstile,
}

impl Turnstile {
    pub const fn new() -> Self {
        Self {
            tickets: Mutex::new(Tickets {
                next: 0,
                serving: 0,
            }),
            changed: Condvar::new(),
        }
    }

    fn state(&self) -> MutexGuard<'_, Tickets> {
        self.tickets.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Block until every caller that arrived earlier has finished.
    pub fn wait_turn(&self) -> Turn<'_> {
        let mut tickets = self.state();
        let mine = tickets.next;
        tickets.next += 1;

        while tickets.serving != mine {
            tickets = self
                .changed
                .wait(tickets)
                .unwrap_or_else(PoisonError::into_inner);
        }

        drop(tickets);

        Turn { turnstile: self }
    }

    /// Callers that hold a ticket, the one being served included.
    #[cfg(test)]
    fn holders(&self) -> u64 {
        let tickets = self.state();

        tickets.next - tickets.serving
    }
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        self.turnstile.state().serving += 1;
        self.turnstile.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        thread,
        time::Duration,
    };

    use super::Turnstile;

    #[test]
    fn waiters_proceed_in_arrival_order() {
        const WAITERS: u64 = 8;

        let turnstile = Arc::new(Turnstile::new());
        let served = Arc::new(Mutex::new(Vec::new()));
        let first = turnstile.wait_turn();
        let mut threads = Vec::new();

        for id in 0..WAITERS {
            let waiting = Arc::clone(&turnstile);
            let served = Arc::clone(&served);
            threads.push(thread::spawn(move || {
                let _turn = waiting.wait_turn();
                served.lock().expect("served list").push(id);
            }));

            // The next waiter arrives only once this one holds its ticket.
            while turnstile.holders() < id + 2 {
                thread::sleep(Duration::from_millis(1));
            }
        }

        assert!(served.lock().expect("served list").is_empty());
        drop(first);

        for thread in threads {
            thread.join().expect("waiter");
        }

        assert_eq!(
            *served.lock().expect("served list"),
            (0..WAITERS).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_panicking_holder_does_not_block_the_queue() {
        let turnstile = Arc::new(Turnstile::new());
        let crashing = Arc::clone(&turnstile);

        let result = thread::spawn(move || {
            let _turn = crashing.wait_turn();
            panic!("dialog helper crashed");
        })
        .join();

        assert!(result.is_err());
        drop(turnstile.wait_turn());
    }
}
