use crate::protocol::{Frame, Command};
use crate::socks5::Target;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use log::{info, warn, error, debug};

fn std_connect(addr: &str) -> std::io::Result<TcpStream> {
    let s = std::net::TcpStream::connect(addr)?;
    s.set_nonblocking(true)?;
    TcpStream::from_std(s)
}

pub async fn run(server_addr: &str, password: &str, retry: u64) -> Result<()> {
    loop {
        info!("connecting to {}...", server_addr);
        match std_connect(server_addr) {
            Ok(stream) => {
                info!("connected to server");
                if let Err(e) = session(stream, password).await {
                    warn!("session ended: {}", e);
                }
            }
            Err(e) => warn!("connection failed: {}", e),
        }
        info!("reconnecting in {}s...", retry);
        tokio::time::sleep(tokio::time::Duration::from_secs(retry)).await;
    }
}

async fn session(mut stream: TcpStream, password: &str) -> Result<()> {
    Frame::new(Command::Auth, 0, password.as_bytes().to_vec())
        .write_to(&mut stream)
        .await?;

    let resp = Frame::read_from(&mut stream).await?;
    match resp.cmd {
        Command::AuthOk => info!("authenticated"),
        Command::AuthFail => {
            anyhow::bail!("auth failed: {}", String::from_utf8_lossy(&resp.data));
        }
        other => anyhow::bail!("unexpected response: {:?}", other),
    }

    let (reader, writer) = stream.into_split();
    let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(256);
    let channels: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let writer_handle = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(frame) = writer_rx.recv().await {
            if let Err(e) = frame.write_to(&mut writer).await {
                error!("write error: {}", e);
                break;
            }
        }
    });

    let mut reader = reader;
    loop {
        let frame = match Frame::read_from(&mut reader).await {
            Ok(f) => f,
            Err(e) => {
                warn!("read error: {}", e);
                break;
            }
        };

        match frame.cmd {
            Command::Connect => {
                let target = Target::deserialize(&frame.data)?;
                let cid = frame.channel_id;
                let wtx = writer_tx.clone();
                let chs = channels.clone();
                tokio::spawn(async move {
                    handle_connect(cid, target, wtx, chs).await;
                });
            }
            Command::Data => {
                let ch = channels.lock().await;
                if let Some(tx) = ch.get(&frame.channel_id) {
                    let _ = tx.send(frame.data).await;
                }
            }
            Command::Close => {
                channels.lock().await.remove(&frame.channel_id);
            }
            Command::Ping => {
                let _ = writer_tx
                    .send(Frame::empty(Command::Pong, 0))
                    .await;
            }
            _ => debug!("unexpected: {:?}", frame.cmd),
        }
    }

    writer_handle.abort();
    Ok(())
}

async fn handle_connect(
    channel_id: u32,
    target: Target,
    writer_tx: mpsc::Sender<Frame>,
    channels: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
) {
    let addr = target.addr_string();
    debug!("connecting to {}", addr);

    let stream = match std_connect(&addr) {
        Ok(s) => {
            let _ = writer_tx
                .send(Frame::empty(Command::ConnectOk, channel_id))
                .await;
            info!("channel {} → {}", channel_id, addr);
            s
        }
        Err(e) => {
            warn!("channel {} connect failed ({}): {}", channel_id, addr, e);
            let _ = writer_tx
                .send(Frame::new(
                    Command::ConnectFail,
                    channel_id,
                    e.to_string().into_bytes(),
                ))
                .await;
            return;
        }
    };

    let (mut target_reader, mut target_writer) = stream.into_split();
    let (data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(64);

    channels.lock().await.insert(channel_id, data_tx);

    let wtx = writer_tx.clone();

    let upstream = tokio::spawn(async move {
        let mut buf = vec![0u8; 32768];
        loop {
            match target_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if wtx
                        .send(Frame::new(Command::Data, channel_id, buf[..n].to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        let _ = wtx.send(Frame::empty(Command::Close, channel_id)).await;
    });

    let downstream = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        while let Some(data) = data_rx.recv().await {
            if target_writer.write_all(&data).await.is_err() {
                break;
            }
        }
    });

    tokio::select! {
        _ = upstream => {}
        _ = downstream => {}
    }

    channels.lock().await.remove(&channel_id);
}
