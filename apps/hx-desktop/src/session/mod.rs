//! Sessions: connect with a PIN, the live connection, reconnect and takeover.

pub mod connect;
pub mod desk;
pub mod lifecycle;
pub mod net;

pub use connect::{Machine as ConnectMachine, Notice, Outcome, State as ConnectState};
pub use desk::{Connector, Desk, Established, RealConnector, Wiring};
pub use lifecycle::{CloseReason, Next, Reconnect};
pub use net::{Event, Link, MgmtError, Session};
