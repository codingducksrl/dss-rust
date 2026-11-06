// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! RefreshScheduler (feature `tokio`). The LOTL URL points at a closed port on 127.0.0.1, so each refresh fails
//! fast without any network, which is enough to observe the schedule.

#![cfg(feature = "tokio")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use dss::EngineBuilder;
use dss::schedule::RefreshScheduler;

fn engine() -> Arc<dss::Engine> {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port(); // now closed
    let mut config = offline_config();
    config.lotl_url = Some(format!("http://127.0.0.1:{port}/eu-lotl.xml"));
    Arc::new(EngineBuilder::new(temp_dir("sched"), &config).build().unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn refreshes_periodically() {
    let scheduler = RefreshScheduler::spawn(engine(), Duration::from_millis(300), true);
    let mut outcomes = scheduler.subscribe();
    for _ in 0..3 {
        tokio::time::timeout(Duration::from_secs(10), outcomes.changed())
            .await
            .unwrap()
            .unwrap();
        let outcome = outcomes.borrow_and_update().clone().unwrap();
        let record = outcome.result.unwrap();
        assert_eq!(record.mode, "online");
        assert!(record.completed);
    }
    scheduler.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_now_does_not_wait_for_the_period() {
    let scheduler = RefreshScheduler::spawn(engine(), Duration::from_secs(3600), false);
    let mut outcomes = scheduler.subscribe();
    assert!(scheduler.refresh_now());
    tokio::time::timeout(Duration::from_secs(10), outcomes.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(outcomes.borrow().as_ref().unwrap().result.is_ok());
    scheduler.stop();
}
