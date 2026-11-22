//! Shared parts of the netem end-to-end test and the performance macro run
//! (`e2e_netem.rs`): the network profiles and namespaces, the X "terminal" whose marks are read
//! back out of the decoded video, the client flow, the server stack and the result types with
//! their thresholds.
#![allow(dead_code)]

pub mod client;
pub mod desk;
pub mod net;
pub mod result;
pub mod stack;
