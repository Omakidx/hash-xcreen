//! WebSocket-over-TLS fallback (stub, replaced in the next commit).

use std::sync::Arc;

use bytes::Bytes;
use hx_proto::channel::{ChannelId, CloseCode};

use crate::{
    client::{ClientHello, ClientOptions, Target},
    conn::{Connection, Inner, Parts, VideoJob},
    error::{Error, Result},
    server::ServerCtx,
    transfer::{TransferKind, TransferSender},
};

pub(crate) enum WsChunk {
    Data(Bytes),
    End,
    Aborted,
}

pub(crate) struct WsTransferSender;

impl WsTransferSender {
    pub(crate) async fn send_data(&mut self, _b: Bytes) -> Result<()> {
        Err(Error::Config("websocket not implemented".into()))
    }
    pub(crate) async fn send_end(&mut self) -> Result<()> {
        Err(Error::Config("websocket not implemented".into()))
    }
    pub(crate) fn abort(self) {}
}

pub(crate) struct WsBackend;

impl WsBackend {
    pub(crate) fn close(&self, _code: CloseCode, _reason: &str) {}
    pub(crate) async fn flush_close(&self) {}
    pub(crate) async fn send_reliable(&self, _ch: ChannelId, _body: Bytes) -> Result<()> {
        Err(Error::Config("websocket not implemented".into()))
    }
    pub(crate) async fn send_datagram(&self, _dg: Bytes) -> Result<()> {
        Err(Error::Config("websocket not implemented".into()))
    }
    pub(crate) async fn send_video(&self, _i: Arc<Inner>, _j: VideoJob) -> Result<()> {
        Err(Error::Config("websocket not implemented".into()))
    }
    pub(crate) async fn open_transfer(
        &self,
        _k: TransferKind,
        _h: hx_proto::pb::TransferHeader,
    ) -> Result<TransferSender> {
        Err(Error::Config("websocket not implemented".into()))
    }
}

pub(crate) struct WsPending;

pub(crate) async fn accept_loop(_l: tokio::net::TcpListener, _ctx: Arc<ServerCtx>) {}

pub(crate) async fn establish_server(_w: WsPending, _ack: Bytes, _p: Parts) -> Result<Connection> {
    Err(Error::Config("websocket not implemented".into()))
}

pub(crate) async fn refuse_server(_w: WsPending, _body: Bytes, _code: CloseCode) -> Result<()> {
    Err(Error::Config("websocket not implemented".into()))
}

pub(crate) async fn connect(
    _tls: &Arc<rustls::ClientConfig>,
    _o: &ClientOptions,
    _t: &Target,
    _h: &ClientHello,
) -> Result<Connection> {
    Err(Error::Config("websocket not implemented".into()))
}
