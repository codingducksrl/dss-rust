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

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

use crate::{Engine, Error, RefreshRecord, Result};

/// The result of one scheduled or requested refresh.
#[derive(Debug, Clone)]
pub struct RefreshOutcome {
    pub finished_at: SystemTime,
    pub result: Result<RefreshRecord>,
}

/// Refreshes the engine's trusted lists every `every`, and on demand. Each refresh runs on tokio's blocking
/// pool (the engine's own refresh thread does the work); validations are not affected.
pub struct RefreshScheduler {
    trigger: mpsc::Sender<()>,
    outcomes: watch::Receiver<Option<RefreshOutcome>>,
    task: JoinHandle<()>,
}

impl RefreshScheduler {
    /// Starts the schedule on the current tokio runtime. With `refresh_on_start`, the first refresh runs
    /// immediately; otherwise after `every`.
    pub fn spawn(engine: Arc<Engine>, every: Duration, refresh_on_start: bool) -> Self {
        let (trigger, mut requests) = mpsc::channel::<()>(1);
        let (publish, outcomes) = watch::channel(None);
        let task = tokio::spawn(async move {
            let first = if refresh_on_start {
                Instant::now()
            } else {
                Instant::now() + every
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
                // A manual refresh restarts the period instead of being followed by a scheduled one.
                ticker.reset();
            }
        });
        RefreshScheduler {
            trigger,
            outcomes,
            task,
        }
    }

    /// Requests a refresh as soon as possible. Returns false if one is already pending.
    pub fn refresh_now(&self) -> bool {
        self.trigger.try_send(()).is_ok()
    }

    /// The latest outcome; `changed()` resolves after each refresh.
    pub fn subscribe(&self) -> watch::Receiver<Option<RefreshOutcome>> {
        self.outcomes.clone()
    }

    /// Stops scheduling. A refresh already running finishes in the background.
    pub fn stop(self) {
        self.task.abort();
    }
}
