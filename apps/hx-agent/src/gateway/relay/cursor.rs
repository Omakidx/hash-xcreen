//! The cursor channel toward one client: shapes in order, positions latest-wins.
//!
//! The pump hands updates over without waiting. At most 16 shapes (4 MiB of them) wait for the
//! sender; beyond that the oldest shape goes (a position that names it is ignored by the client,
//! protocol 5.4, and the session resends the shape on the next IDR request). Positions are one
//! slot: a burst collapses into the newest, and a position is only ever sent after the shapes
//! that were queued before it, so it never overtakes the shape it names.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use hx_proto::channel::CloseCode;
use hx_proto::pb::{CursorEvent, CursorPosition, CursorShape, cursor_event::Event};
use hx_transport::Connection;
use tokio::sync::{Notify, watch};

use super::util::lock;
use crate::link::CursorUpdate;

const MAX_SHAPES: usize = 16;
const MAX_SHAPE_BYTES: usize = 4 * 1024 * 1024;
/// A cursor write that takes this long: the client does not read.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Default)]
struct State {
    shapes: VecDeque<CursorShape>,
    bytes: usize,
    position: Option<CursorPosition>,
}

/// Cursor updates waiting for the sender task.
#[derive(Default)]
pub(super) struct CursorSlot {
    state: Mutex<State>,
    notify: Notify,
}

impl CursorSlot {
    pub(super) fn push(&self, u: CursorUpdate) {
        {
            let mut s = lock(&self.state);
            match u {
                CursorUpdate::Shape(shape) => {
                    s.bytes += shape.rgba.len();
                    s.shapes.push_back(shape);
                    while s.shapes.len() > MAX_SHAPES || s.bytes > MAX_SHAPE_BYTES {
                        match s.shapes.pop_front() {
                            Some(old) => s.bytes -= old.rgba.len(),
                            None => break,
                        }
                    }
                }
                CursorUpdate::Position(p) => s.position = Some(p),
            }
        }
        self.notify.notify_one();
    }

    fn take(&self) -> (Vec<CursorShape>, Option<CursorPosition>) {
        let mut s = lock(&self.state);
        s.bytes = 0;
        (s.shapes.drain(..).collect(), s.position.take())
    }

    /// Bytes of shapes waiting (tests).
    #[cfg(test)]
    fn queued(&self) -> (usize, usize) {
        let s = lock(&self.state);
        (s.shapes.len(), s.bytes)
    }
}

/// The sender task: shapes first, in order, then the newest position.
pub(super) async fn sender(
    conn: Connection,
    slot: std::sync::Arc<CursorSlot>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            () = slot.notify.notified() => {}
        }
        let (shapes, position) = slot.take();
        let events = shapes
            .into_iter()
            .map(Event::Shape)
            .chain(position.map(Event::Position));
        for e in events {
            let msg = CursorEvent { event: Some(e) };
            match tokio::time::timeout(WRITE_TIMEOUT, conn.send_cursor(&msg)).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return,
                Err(_) => {
                    let c = conn.clone();
                    tokio::spawn(async move { c.close(CloseCode::Busy, "not reading").await });
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(id: u64, bytes: usize) -> CursorUpdate {
        CursorUpdate::Shape(CursorShape {
            id,
            width: 1,
            height: 1,
            hotspot_x: 0,
            hotspot_y: 0,
            rgba: vec![0; bytes].into(),
        })
    }

    #[test]
    fn shapes_are_bounded_and_positions_collapse() {
        let slot = CursorSlot::default();
        for id in 0..40 {
            slot.push(shape(id, 1_000));
        }
        assert_eq!(slot.queued().0, MAX_SHAPES);
        // Huge shapes: the byte bound applies too.
        for id in 100..110 {
            slot.push(shape(id, 1_500_000));
        }
        assert!(slot.queued().1 <= MAX_SHAPE_BYTES);
        for x in 0..1000 {
            slot.push(CursorUpdate::Position(CursorPosition {
                x,
                y: 0,
                shape_id: 109,
                visible: true,
            }));
        }
        let (shapes, pos) = slot.take();
        assert!(!shapes.is_empty());
        assert_eq!(pos.unwrap().x, 999, "latest wins");
        assert_eq!(slot.queued(), (0, 0));
    }
}
