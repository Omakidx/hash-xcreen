//! s2-client: headless QUIC client; reassembles frame streams in order, decodes with libavcodec
//! (software H.264) and writes a per-frame timing CSV plus a JSON summary.

use anyhow::{Result, bail};
use crossbeam_channel::{Receiver, Sender, unbounded};
use ffmpeg_next as ffmpeg;
use s2::wire::{self, FrameHeader, HEADER_LEN};
use s2::{Args, now_ns, process_cpu_ns};
use std::collections::BTreeMap;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

struct RxFrame {
    hdr: FrameHeader,
    payload: Vec<u8>,
    t_recv: u64,
}

#[derive(Debug)]
struct SkipVerify;
impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ECDSA_NISTP256_SHA256, rustls::SignatureScheme::ED25519]
    }
}

#[derive(Default)]
struct Counters {
    bytes: AtomicU64,
    streams_ok: AtomicU64,
    streams_reset: AtomicU64,
    cursor_msgs: AtomicU64,
    cursor_lat_sum_ns: AtomicU64,
    cursor_lat_max_ns: AtomicU64,
}

#[allow(clippy::too_many_arguments)]
fn decode_thread(
    rx: Receiver<RxFrame>,
    threads: usize,
    warmup_ns: u64,
    duration_ns: u64,
    rows_path: String,
    summary_path: String,
    ctr: Arc<Counters>,
) -> Result<()> {
    let codec = ffmpeg::decoder::find(ffmpeg::codec::Id::H264).ok_or_else(|| anyhow::anyhow!("no h264 decoder"))?;
    let mut ctx = ffmpeg::codec::context::Context::new_with_codec(codec);
    ctx.set_flags(ffmpeg::codec::Flags::LOW_DELAY);
    ctx.set_threading(ffmpeg::threading::Config { kind: ffmpeg::threading::Type::Slice, count: threads });
    let mut dec = ctx.decoder().video()?;
    let mut frame = ffmpeg::frame::Video::empty();

    let mut rows = Vec::<[u64; 14]>::with_capacity(1 << 16);
    let mut pending: BTreeMap<u32, RxFrame> = BTreeMap::new();
    let mut next: u32 = 0;
    let (mut t0, mut cpu0, mut bytes0, mut started) = (0u64, 0u64, 0u64, false);
    let _ = &mut started;
    let mut dropped_before_key = 0u64;
    let mut resync_jumps = 0u64;
    let mut stalled_ns_max = 0u64;
    let mut gap_since: Option<u64> = None;
    let t_start = now_ns();
    let mut t_end = 0u64;
    let mut cpu1 = 0u64;
    let mut bytes1 = 0u64;
    let mut decoded_frames = 0u64;

    loop {
        match rx.recv_timeout(std::time::Duration::from_millis(50)) {
            Ok(f) => {
                pending.insert(f.hdr.frame_no, f);
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Err(_) => break,
        }
        // Ordered delivery with resync: a key frame ahead of `next` makes everything older irrelevant.
        loop {
            if let Some((&k, f)) = pending.iter().find(|(k, f)| **k > next && f.hdr.flags & wire::FLAG_KEY != 0 && f.hdr.flags & wire::FLAG_RESYNC != 0) {
                let _ = f;
                let old: Vec<u32> = pending.keys().copied().filter(|x| *x < k).collect();
                for o in old {
                    pending.remove(&o);
                    dropped_before_key += 1;
                }
                next = k;
                resync_jumps += 1;
                gap_since = None;
            }
            let Some(f) = pending.remove(&next) else {
                if !pending.is_empty() && gap_since.is_none() {
                    gap_since = Some(now_ns());
                }
                break;
            };
            if let Some(g) = gap_since.take() {
                stalled_ns_max = stalled_ns_max.max(now_ns() - g);
            }
            next = f.hdr.frame_no + 1;
            let t_dec_start = now_ns();
            let pkt = ffmpeg::Packet::copy(&f.payload);
            dec.send_packet(&pkt)?;
            let mut got = false;
            while dec.receive_frame(&mut frame).is_ok() {
                got = true;
            }
            let t_dec_end = now_ns();
            if !got {
                continue;
            }
            decoded_frames += 1;
            if started && t_end == 0 && t_dec_end >= t0 && t_dec_end - t0 <= duration_ns {
                let h = &f.hdr;
                rows.push([
                    h.frame_no as u64, h.flags as u64, h.len as u64, h.t_damage, h.t_capture, h.t_convert, h.t_enc_start,
                    h.t_enc_end, h.t_send, f.t_recv, t_dec_start, t_dec_end, 0, 0,
                ]);
            }
        }
        // Time-based measurement window (idle desktops produce no frames at all).
        let now = now_ns();
        if !started && now - t_start > warmup_ns {
            started = true;
            t0 = now;
            cpu0 = process_cpu_ns();
            bytes0 = ctr.bytes.load(Relaxed);
        }
        if started && t_end == 0 && now - t0 > duration_ns {
            t_end = now;
            cpu1 = process_cpu_ns();
            bytes1 = ctr.bytes.load(Relaxed);
            break;
        }
    }
    if !started || t_end == 0 {
        bail!("connection ended before the measurement window completed");
    }
    let mut f = std::io::BufWriter::new(std::fs::File::create(&rows_path)?);
    writeln!(f, "frame_no,flags,len,t_damage,t_capture,t_convert,t_enc_start,t_enc_end,t_send,t_recv,t_dec_start,t_dec_end")?;
    for r in &rows {
        writeln!(f, "{}", r[..12].iter().map(|v| v.to_string()).collect::<Vec<_>>().join(","))?;
    }
    f.flush()?;
    let wall = (t_end - t0) as f64 / 1e9;
    let cursor_n = ctr.cursor_msgs.load(Relaxed).max(1);
    let summary = format!(
        "{{\"t0_ns\":{},\"t1_ns\":{},\"wall_s\":{:.3},\"client_cpu_cores\":{:.4},\"rx_bytes\":{},\"rx_mbps\":{:.3},\"frames\":{},\"fps\":{:.2},\"decoded_total\":{},\"streams_ok\":{},\"streams_reset\":{},\"resync_jumps\":{},\"dropped_before_key\":{},\"max_gap_stall_ms\":{:.1},\"cursor_msgs\":{},\"cursor_lat_avg_ms\":{:.3},\"cursor_lat_max_ms\":{:.3}}}\n",
        t0,
        t_end,
        wall,
        (cpu1 - cpu0) as f64 / 1e9 / wall,
        bytes1 - bytes0,
        (bytes1 - bytes0) as f64 * 8.0 / 1e6 / wall,
        rows.len(),
        rows.len() as f64 / wall,
        decoded_frames,
        ctr.streams_ok.load(Relaxed),
        ctr.streams_reset.load(Relaxed),
        resync_jumps,
        dropped_before_key,
        stalled_ns_max as f64 / 1e6,
        ctr.cursor_msgs.load(Relaxed),
        ctr.cursor_lat_sum_ns.load(Relaxed) as f64 / cursor_n as f64 / 1e6,
        ctr.cursor_lat_max_ns.load(Relaxed) as f64 / 1e6,
    );
    std::fs::write(&summary_path, summary)?;
    Ok(())
}

async fn read_frame_stream(mut s: quinn::RecvStream, tx: Sender<RxFrame>, ctr: Arc<Counters>) {
    let mut kind = [0u8; 1];
    if s.read_exact(&mut kind).await.is_err() {
        ctr.streams_reset.fetch_add(1, Relaxed);
        return;
    }
    if kind[0] == wire::KIND_CURSOR {
        let mut lenb = [0u8; 5];
        let mut buf = Vec::new();
        while s.read_exact(&mut lenb).await.is_ok() {
            let len = u32::from_le_bytes(lenb[1..5].try_into().unwrap()) as usize;
            if len > 1 << 20 {
                return;
            }
            buf.resize(len, 0);
            if s.read_exact(&mut buf).await.is_err() {
                return;
            }
            if lenb[0] == wire::CUR_POS && len == 12 {
                let t = u64::from_le_bytes(buf[4..12].try_into().unwrap());
                let lat = now_ns().saturating_sub(t);
                ctr.cursor_msgs.fetch_add(1, Relaxed);
                ctr.cursor_lat_sum_ns.fetch_add(lat, Relaxed);
                ctr.cursor_lat_max_ns.fetch_max(lat, Relaxed);
            }
        }
        return;
    }
    let mut hb = [0u8; HEADER_LEN];
    hb[0] = kind[0];
    if s.read_exact(&mut hb[1..]).await.is_err() {
        ctr.streams_reset.fetch_add(1, Relaxed);
        return;
    }
    let Some(hdr) = FrameHeader::decode(&hb) else { return };
    if hdr.len > 64 << 20 {
        return;
    }
    let mut payload = vec![0u8; hdr.len as usize];
    if s.read_exact(&mut payload).await.is_err() {
        ctr.streams_reset.fetch_add(1, Relaxed);
        return;
    }
    let t_recv = now_ns();
    ctr.bytes.fetch_add((HEADER_LEN + payload.len()) as u64, Relaxed);
    ctr.streams_ok.fetch_add(1, Relaxed);
    let _ = tx.send(RxFrame { hdr, payload, t_recv });
}

fn main() -> Result<()> {
    let a = Args::parse();
    let server: SocketAddr = a.get_str("server", "127.0.0.1:4433").parse()?;
    let warmup = (a.get::<f64>("warmup", 3.0) * 1e9) as u64;
    let duration = (a.get::<f64>("duration", 20.0) * 1e9) as u64;
    let out = a.get_str("out", "/tmp/s2-client");
    let dec_threads: usize = a.get("dec-threads", 4);
    ffmpeg::init()?;
    ffmpeg::util::log::set_level(ffmpeg::util::log::Level::Warning);

    let (tx, rx) = unbounded::<RxFrame>();
    let ctr = Arc::new(Counters::default());
    let dec = {
        let ctr = ctr.clone();
        let (rp, sp) = (format!("{out}-frames.csv"), format!("{out}-summary.json"));
        std::thread::Builder::new().name("decode".into()).spawn(move || decode_thread(rx, dec_threads, warmup, duration, rp, sp, ctr))?
    };

    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
    rt.block_on(async {
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipVerify))
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"hx/1".to_vec()];
        let mut cc = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls)?));
        let mut tc = quinn::TransportConfig::default();
        tc.max_concurrent_uni_streams(1024u32.into());
        tc.stream_receive_window((8u32 * 1024 * 1024).into());
        tc.receive_window((64u32 * 1024 * 1024).into());
        tc.initial_rtt(std::time::Duration::from_millis(100));
        tc.keep_alive_interval(Some(std::time::Duration::from_secs(2)));
        cc.transport_config(Arc::new(tc));
        let mut ep = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
        ep.set_default_client_config(cc);
        let conn = ep.connect(server, "s2")?.await?;
        eprintln!("s2-client: connected to {server}");
        loop {
            tokio::select! {
                s = conn.accept_uni() => {
                    let Ok(s) = s else { break };
                    tokio::spawn(read_frame_stream(s, tx.clone(), ctr.clone()));
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                    if dec.is_finished() { break; }
                }
            }
        }
        conn.close(0u32.into(), b"done");
        ep.wait_idle().await;
        Ok::<_, anyhow::Error>(())
    })?;
    match dec.join() {
        Ok(r) => r,
        Err(_) => bail!("decode thread panicked"),
    }
}
