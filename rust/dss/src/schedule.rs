// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! Periodic trusted-list refresh on a tokio runtime (feature `tokio`).
//!
//! ```no_run
//! # async fn demo(engine: std::sync::Arc<dss::Engine>) {
//! use std::time::Duration;
//! let scheduler = dss::schedule::RefreshScheduler::spawn(engine, Duration::from_secs(6 * 3600), true);
//! scheduler.refresh_now(); // e.g. from an admin endpoint
//! let mut outcomes = scheduler.subscribe();
//! outcomes.changed().await.ok();
//! # }
//! ```

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

use crate::{Engine, Error, RefreshRecord, Result};

/// The result of one scheduled or requested refresh.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RefreshOutcome {
    /// When the refresh finished.
    pub finished_at: SystemTime,
    /// What it returned: the record, or the engine's error ([`ErrorCode::RefreshInProgress`](crate::ErrorCode::RefreshInProgress)
    /// when a refresh started outside the scheduler was running, [`ErrorCode::TlRefreshFailed`](crate::ErrorCode::TlRefreshFailed)
    /// when nothing was published).
    pub result: Result<RefreshRecord>,
}

/// What [`RefreshScheduler::request_refresh`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RefreshRequest {
    /// A refresh starts as soon as possible (or is already running: its outcome serves this request too).
    Started,
    /// A request is already waiting; this one adds nothing.
    AlreadyPending,
    /// The scheduler is stopped: nothing will run. Refresh through [`Engine::refresh_trusted_lists`] instead.
    Stopped,
}

/// Refreshes the engine's trusted lists every `every`, and on demand. Each refresh runs on tokio's blocking
/// pool (the engine's own refresh thread does the work); validations are not affected.
///
/// Two ways to end the schedule:
/// - [`stop`](Self::stop) aborts it at once; a refresh in flight finishes in the background and its outcome is
///   not published.
/// - Dropping the handle lets a refresh in flight finish and publishes its outcome to the subscribers that are
///   left, then the schedule ends (no further tick fires) and the outcome channel closes. A shutdown that must
///   wait for a running refresh subscribes first, drops the handle, and awaits `changed()` until it fails.
///
/// The handle holds an `Arc` of the engine until it is dropped; either way the engine is released at the end.
pub struct RefreshScheduler {
    trigger: mpsc::Sender<()>,
    outcomes: watch::Receiver<Option<RefreshOutcome>>,
    task: JoinHandle<()>,
}

impl std::fmt::Debug for RefreshScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshScheduler")
            .field("running", &self.is_running())
            .finish()
    }
}

impl RefreshScheduler {
    /// Starts the schedule on the current tokio runtime. With `refresh_on_start`, the first refresh runs
    /// immediately; otherwise after `every`. A manual refresh restarts the period.
    ///
    /// # Panics
    ///
    /// When `every` is zero or too long to schedule; [`try_spawn`](Self::try_spawn) returns that as an error.
    pub fn spawn(engine: Arc<Engine>, every: Duration, refresh_on_start: bool) -> Self {
        Self::try_spawn(engine, every, refresh_on_start).unwrap_or_else(|e| panic!("RefreshScheduler: {e}"))
    }

    /// As [`spawn`](Self::spawn), failing with [`Error::Argument`] instead of panicking when `every` is zero or
    /// too long to schedule.
    pub fn try_spawn(engine: Arc<Engine>, every: Duration, refresh_on_start: bool) -> Result<Self> {
        if every.is_zero() {
            return Err(Error::Argument("refresh period must be more than zero".into()));
        }
        if every
            .checked_mul(2)
            .and_then(|d| Instant::now().checked_add(d))
            .is_none()
        {
            return Err(Error::Argument(format!(
                "refresh period {every:?} is too long to schedule"
            )));
        }
        let (trigger, mut requests) = mpsc::channel::<()>(1);
        let (publish, outcomes) = watch::channel(None);
        let task = tokio::spawn(async move {
            let now = Instant::now();
            let first = if refresh_on_start {
                now
            } else {
                now.checked_add(every).unwrap_or(now)
            };
            let mut ticker = tokio::time::interval_at(first, every);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    request = requests.recv() => if request.is_none() { break },
                }
                let e = Arc::clone(&engine);
                let result = match tokio::task::spawn_blocking(move || e.refresh_trusted_lists()).await {
                    Ok(r) => r,
                    Err(_) => Err(Error::Closed),
                };
                let _ = publish.send(Some(RefreshOutcome {
                    finished_at: SystemTime::now(),
                    result,
                }));
                // A request made while that refresh ran is served by it: the engine would have refused a second
                // refresh anyway, and a back-to-back download would bring nothing new.
                while requests.try_recv().is_ok() {}
                // A manual refresh restarts the period instead of being followed by a scheduled one.
                ticker.reset();
            }
        });
        Ok(RefreshScheduler {
            trigger,
            outcomes,
            task,
        })
    }

    /// Requests a refresh as soon as possible. Returns true when it is [`Started`](RefreshRequest::Started):
    /// false when a request is already pending or the scheduler is stopped ([`request_refresh`](Self::request_refresh)
    /// tells the two apart).
    pub fn refresh_now(&self) -> bool {
        self.request_refresh() == RefreshRequest::Started
    }

    /// Requests a refresh as soon as possible, and says whether it will run. A request made while a refresh is
    /// running is served by that refresh (see [`RefreshOutcome`]).
    pub fn request_refresh(&self) -> RefreshRequest {
        match self.trigger.try_send(()) {
            Ok(()) => RefreshRequest::Started,
            Err(TrySendError::Full(())) => RefreshRequest::AlreadyPending,
            Err(TrySendError::Closed(())) => RefreshRequest::Stopped,
        }
    }

    /// Whether the schedule is still running: false after [`stop`](Self::stop), or if the task ended on its own
    /// (which a panic in it would do).
    pub fn is_running(&self) -> bool {
        !self.task.is_finished()
    }

    /// The latest outcome; `changed()` resolves after each refresh.
    pub fn subscribe(&self) -> watch::Receiver<Option<RefreshOutcome>> {
        self.outcomes.clone()
    }

    /// Stops scheduling at once. A refresh already running finishes in the background (its outcome is not
    /// published); drop the handle instead to have it published (see [`RefreshScheduler`]).
    pub fn stop(self) {
        self.task.abort();
    }
}
