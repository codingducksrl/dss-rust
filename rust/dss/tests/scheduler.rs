// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! RefreshScheduler (feature `tokio`). The LOTL URL points at a closed port on 127.0.0.1, so each refresh fails
//! fast (milliseconds) without any network, which is enough to observe the schedule. Timing assertions leave a
//! wide margin: a period of 1 s, checks at a quarter and at twice the period.

#![cfg(feature = "tokio")]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use dss::schedule::{RefreshOutcome, RefreshRequest, RefreshScheduler};
use dss::{EngineBuilder, ErrorCode, Http};

const PERIOD: Duration = Duration::from_secs(1);
const SOON: Duration = Duration::from_millis(250);
const LATE: Duration = Duration::from_secs(3);

/// An engine whose online refresh fails at once (closed port), after the directory it caches in: bind the
/// tuple in this order, so that the engine is dropped before its directory (see `common::TempDir`).
fn engine() -> (TempDir, Arc<dss::Engine>) {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port(); // now closed
    let mut config = offline_config();
    config.lotl_url = Some(format!("http://127.0.0.1:{port}/eu-lotl.xml"));
    let cache = temp_dir("sched");
    let engine = Arc::new(EngineBuilder::new(&cache, &config).build().unwrap());
    (cache, engine)
}

/// Waits up to `within` for the next outcome.
async fn next_outcome(
    outcomes: &mut tokio::sync::watch::Receiver<Option<RefreshOutcome>>,
    within: Duration,
) -> Option<RefreshOutcome> {
    match tokio::time::timeout(within, outcomes.changed()).await {
        Ok(Ok(())) => outcomes.borrow_and_update().clone(),
        _ => None,
    }
}

fn assert_online(outcome: &RefreshOutcome) {
    match &outcome.result {
        Ok(record) => assert_eq!(record.mode, "online"),
        // A library that reports an unpublished refresh as an error: still an online refresh that ran.
        Err(e) => assert_eq!(e.code(), Some(ErrorCode::TlRefreshFailed), "{e}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_on_start_runs_at_once_and_then_every_period() {
    let (_cache, engine) = engine();
    let started = Instant::now();
    let scheduler = RefreshScheduler::spawn(engine, PERIOD, true);
    let mut outcomes = scheduler.subscribe();
    let first = next_outcome(&mut outcomes, LATE).await.expect("first refresh");
    assert_online(&first);
    assert!(
        started.elapsed() < PERIOD,
        "refresh_on_start ran after {:?}",
        started.elapsed()
    );

    let second_at = {
        let outcome = next_outcome(&mut outcomes, LATE).await.expect("second refresh");
        assert_online(&outcome);
        Instant::now()
    };
    let gap = second_at.duration_since(started);
    assert!(
        gap >= PERIOD - SOON && gap <= PERIOD + LATE,
        "second refresh after {gap:?}"
    );
    let third = next_outcome(&mut outcomes, LATE).await.expect("third refresh");
    assert_online(&third);
    let gap = second_at.elapsed();
    assert!(gap >= PERIOD - SOON, "third refresh only {gap:?} after the second");
    assert!(scheduler.is_running());
    scheduler.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn without_refresh_on_start_the_first_refresh_waits_a_period() {
    let (_cache, engine) = engine();
    let started = Instant::now();
    let scheduler = RefreshScheduler::spawn(engine, PERIOD, false);
    let mut outcomes = scheduler.subscribe();
    assert!(outcomes.borrow().is_none());
    assert!(
        next_outcome(&mut outcomes, SOON).await.is_none(),
        "a refresh ran within {SOON:?} although refresh_on_start is false"
    );
    let first = next_outcome(&mut outcomes, LATE).await.expect("first refresh");
    assert_online(&first);
    assert!(
        started.elapsed() >= PERIOD - SOON,
        "first refresh after {:?}",
        started.elapsed()
    );
    scheduler.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_now_runs_at_once_and_restarts_the_period() {
    let (_cache, engine) = engine();
    let scheduler = RefreshScheduler::spawn(engine, PERIOD, false);
    let mut outcomes = scheduler.subscribe();
    tokio::time::sleep(PERIOD / 2).await;
    let requested = Instant::now();
    assert_eq!(scheduler.request_refresh(), RefreshRequest::Started);
    let manual = next_outcome(&mut outcomes, LATE).await.expect("the requested refresh");
    assert_online(&manual);
    assert!(requested.elapsed() < SOON, "refresh_now took {:?}", requested.elapsed());

    // The next scheduled refresh is a full period after the manual one, not half a period later.
    assert!(
        next_outcome(&mut outcomes, PERIOD / 2).await.is_none(),
        "a scheduled refresh ran less than a period after the manual one"
    );
    let scheduled = next_outcome(&mut outcomes, LATE).await.expect("the scheduled refresh");
    assert_online(&scheduled);
    assert!(
        requested.elapsed() >= PERIOD - SOON,
        "scheduled refresh {:?} after the manual one",
        requested.elapsed()
    );
    scheduler.stop();
}

/// Requests made while a refresh runs are served by that refresh: the slot is drained afterwards, so no
/// back-to-back refresh follows (the engine would have refused it anyway).
#[tokio::test(flavor = "multi_thread")]
async fn requests_during_a_refresh_are_coalesced() {
    let (_cache, engine, _listener) = blocked_engine();
    let scheduler = RefreshScheduler::spawn(engine, Duration::from_secs(3600), false);
    let mut outcomes = scheduler.subscribe();
    let requested = Instant::now();
    assert_eq!(scheduler.request_refresh(), RefreshRequest::Started);
    tokio::time::sleep(SOON).await; // the refresh is now stuck on the never-answering server
    assert_eq!(
        scheduler.request_refresh(),
        RefreshRequest::Started,
        "accepted: served by the running one"
    );
    assert_eq!(scheduler.request_refresh(), RefreshRequest::AlreadyPending);
    let first = next_outcome(&mut outcomes, Duration::from_secs(20))
        .await
        .expect("the requested refresh");
    assert_online(&first);
    assert!(
        requested.elapsed() >= Duration::from_secs(1),
        "the refresh waited for the response timeout"
    );
    assert!(
        next_outcome(&mut outcomes, Duration::from_secs(5)).await.is_none(),
        "a second refresh followed the coalesced requests"
    );
    scheduler.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_ends_the_schedule() {
    let (_cache, engine) = engine();
    let scheduler = RefreshScheduler::spawn(engine, PERIOD, true);
    let mut outcomes = scheduler.subscribe();
    assert_online(&next_outcome(&mut outcomes, LATE).await.expect("first refresh"));
    let trigger_after_stop = scheduler.subscribe();
    scheduler.stop();
    assert!(
        next_outcome(&mut outcomes, 2 * PERIOD).await.is_none(),
        "a refresh ran after stop()"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while trigger_after_stop.has_changed().is_ok() {
        assert!(
            Instant::now() < deadline,
            "the outcome channel did not close with the task"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_periods_are_refused_before_the_task_starts() {
    let (_cache, engine) = engine();
    let err = RefreshScheduler::try_spawn(Arc::clone(&engine), Duration::ZERO, true).unwrap_err();
    assert!(matches!(err, dss::Error::Argument(_)), "{err}");
    let err = RefreshScheduler::try_spawn(Arc::clone(&engine), Duration::MAX, false).unwrap_err();
    assert!(matches!(err, dss::Error::Argument(_)), "{err}");
    let err = RefreshScheduler::try_spawn(
        Arc::clone(&engine),
        Duration::from_secs(3_000_000_000_000_000 * 3600),
        false,
    )
    .unwrap_err();
    assert!(err.to_string().contains("too long"), "{err}");
    let ok = RefreshScheduler::try_spawn(engine, Duration::from_secs(6 * 3600), false).unwrap();
    assert!(ok.is_running());
    ok.stop();
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "refresh period must be more than zero")]
async fn spawn_panics_synchronously_on_a_zero_period() {
    let (_cache, engine) = engine();
    let _ = RefreshScheduler::spawn(engine, Duration::ZERO, true);
}

/// An engine whose online refresh is stuck until the response timeout (about 2 s): the listener accepts
/// connections and never answers. The cache directory comes first, as in [`engine`].
fn blocked_engine() -> (TempDir, Arc<dss::Engine>, std::net::TcpListener) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut config = offline_config();
    config.lotl_url = Some(format!("http://127.0.0.1:{port}/eu-lotl.xml"));
    config.http = Some(Http {
        connect_timeout_ms: Some(1000),
        response_timeout_ms: Some(2000),
        block_private_addresses: Some(false), // the test server is on 127.0.0.1
        ..Default::default()
    });
    let cache = temp_dir("sched");
    let engine = Arc::new(EngineBuilder::new(&cache, &config).build().unwrap());
    (cache, engine, listener)
}

/// Dropping the handle (not stop()) while a refresh is in flight: that refresh finishes and its outcome reaches
/// a subscriber taken before the drop, then the schedule ends and the outcome channel closes. dss-server's
/// shutdown waits for a scheduled refresh this way.
#[tokio::test(flavor = "multi_thread")]
async fn dropping_the_handle_publishes_the_refresh_in_flight_then_ends() {
    let (_cache, engine, _listener) = blocked_engine();
    let scheduler = RefreshScheduler::spawn(Arc::clone(&engine), PERIOD, false);
    let mut outcomes = scheduler.subscribe();
    let requested = Instant::now();
    assert_eq!(scheduler.request_refresh(), RefreshRequest::Started);
    tokio::time::sleep(SOON).await; // the refresh is now stuck on the never-answering server
    assert!(engine.trusted_list_status().unwrap().refresh_in_progress);
    drop(scheduler);
    let outcome = next_outcome(&mut outcomes, Duration::from_secs(20))
        .await
        .expect("the outcome of the refresh in flight");
    assert_online(&outcome);
    assert!(
        requested.elapsed() >= Duration::from_secs(1),
        "the refresh waited for the response timeout"
    );
    // The schedule ended: the channel closes without another outcome, within the period a tick would take.
    match tokio::time::timeout(2 * PERIOD, outcomes.changed()).await {
        Ok(Err(_)) => {}
        Ok(Ok(())) => panic!("a refresh ran after the handle was dropped"),
        Err(_) => panic!("the outcome channel did not close after the refresh in flight"),
    }
    assert_eq!(Arc::strong_count(&engine), 1, "the task released the engine");
}

/// The scheduler's refresh finds the engine busy with a refresh started elsewhere: the outcome carries the
/// engine's RefreshInProgress error instead of a record.
#[tokio::test(flavor = "multi_thread")]
async fn an_outcome_carries_the_engine_error() {
    let (_cache, engine, _listener) = blocked_engine();
    let blocked = {
        let engine = Arc::clone(&engine);
        std::thread::spawn(move || engine.refresh_trusted_lists())
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while !engine.trusted_list_status().unwrap().refresh_in_progress {
        assert!(Instant::now() < deadline, "refresh never started");
        std::thread::sleep(Duration::from_millis(20));
    }
    let scheduler = RefreshScheduler::spawn(Arc::clone(&engine), Duration::from_secs(3600), false);
    let mut outcomes = scheduler.subscribe();
    assert!(scheduler.refresh_now());
    let outcome = next_outcome(&mut outcomes, LATE).await.expect("an outcome");
    let err = outcome.result.unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::RefreshInProgress), "{err}");
    scheduler.stop();
    let _ = blocked.join().unwrap();
}
