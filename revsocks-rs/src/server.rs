use crate::protocol::{Frame, Command};
use crate::socks5;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tokio::io::AsyncReadExt;
use log::{info, warn, error, debug};

struct AgentConn {
    writer_tx: mpsc::Sender<Frame>,
    channels: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
    pending: Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>>,
}

pub async fn run(
    agent_addr: &str,
    socks_addr: &str,
    password: &str,
    socks_auth: bool,
    socks_password: Option<String>,
) -> Result<()> {
    let agent_listener = TcpListener::bind(agent_addr).await?;
    let socks_listener = TcpListener::bind(socks_addr).await?;

    info!("agent listener on {}", agent_addr);
    info!("SOCKS5 listener on {}", socks_addr);

    let agent_state: Arc<RwLock<Option<AgentConn>>> = Arc::new(RwLock::new(None));
    let channel_counter = Arc::new(AtomicU32::new(1));

    let state_for_agents = agent_state.clone();
    let password = password.to_string();

    let agent_task = tokio::spawn(async move {
        loop {
            match agent_listener.accept().await {
                Ok((stream, addr)) => {
                    info!("agent connected from {}", addr);
                    let state = state_for_agents.clone();
                    let pw = password.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_agent(stream, state, &pw).await {
                            warn!("agent disconnected: {}", e);
                        }
                    });
                }
                Err(e) => error!("agent accept error: {}", e),
            }
        }
    });

    let state_for_socks = agent_state.clone();

    let socks_task = tokio::spawn(async move {
        loop {
            match socks_listener.accept().await {
                Ok((stream, addr)) => {
                    debug!("SOCKS client from {}", addr);
                    let state = state_for_socks.clone();
                    let counter = channel_counter.clone();
                    let socks_pw = socks_password.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_socks_client(
                            stream, state, counter, socks_auth, socks_pw.as_deref(),
                        ).await {
                            debug!("SOCKS client ended: {}", e);
                        }
                    });
                }
                Err(e) => error!("SOCKS accept error: {}", e),
            }
        }
    });

    tokio::select! {
        _ = agent_task => {}
        _ = socks_task => {}
    }
    Ok(())
}

async fn handle_agent(
    mut stream: TcpStream,
    state: Arc<RwLock<Option<AgentConn>>>,
    password: &str,
) -> Result<()> {
    let frame = Frame::read_from(&mut stream).await?;
    if frame.cmd != Command::Auth {
        anyhow::bail!("expected AUTH, got {:?}", frame.cmd);
    }
    if String::from_utf8_lossy(&frame.data) != password {
        Frame::new(Command::AuthFail, 0, b"bad password".to_vec())
            .write_to(&mut stream).await?;
        anyhow::bail!("agent auth failed");
    }
    Frame::empty(Command::AuthOk, 0).write_to(&mut stream).await?;
    info!("agent authenticated");

    let (reader, writer) = stream.into_split();
    let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(256);
    let channels: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let pending: Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    {
        let mut s = state.write().await;
        *s = Some(AgentConn {
            writer_tx: writer_tx.clone(),
            channels: channels.clone(),
            pending: pending.clone(),
        });
    }

    let writer_handle = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(frame) = writer_rx.recv().await {
            if let Err(e) = frame.write_to(&mut writer).await {
                error!("agent write error: {}", e);
                break;
            }
        }
    });

    let keepalive_tx = writer_tx.clone();
    let keepalive_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            if keepalive_tx.send(Frame::empty(Command::Ping, 0)).await.is_err() {
                break;
            }
        }
    });

    let mut reader = reader;
    loop {
        let frame = match Frame::read_from(&mut reader).await {
            Ok(f) => f,
            Err(e) => {
                warn!("agent read error: {}", e);
                break;
            }
        };

        match frame.cmd {
            Command::ConnectOk => {
                if let Some(tx) = pending.lock().await.remove(&frame.channel_id) {
                    let _ = tx.send(true);
                }
            }
            Command::ConnectFail => {
                if let Some(tx) = pending.lock().await.remove(&frame.channel_id) {
                    let _ = tx.send(false);
                }
                channels.lock().await.remove(&frame.channel_id);
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
            Command::Pong => {
                debug!("pong from agent");
            }
            _ => {
                debug!("unexpected frame from agent: {:?}", frame.cmd);
            }
        }
    }

    keepalive_handle.abort();
    writer_handle.abort();

    // Clean up all pending connects
    {
        let mut p = pending.lock().await;
        for (_, tx) in p.drain() {
            let _ = tx.send(false);
        }
    }

    {
        let mut s = state.write().await;
        *s = None;
    }
    info!("agent state cleared");
    Ok(())
}

async fn handle_socks_client(
    mut stream: TcpStream,
    agent_state: Arc<RwLock<Option<AgentConn>>>,
    counter: Arc<AtomicU32>,
    socks_auth: bool,
    socks_password: Option<&str>,
) -> Result<()> {
    let target = socks5::handshake(&mut stream, socks_auth, socks_password).await?;
    debug!("SOCKS CONNECT → {}:{}", target.host, target.port);

    let channel_id = counter.fetch_add(1, Ordering::Relaxed);
    let (data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(64);
    let (connect_tx, connect_rx) = oneshot::channel::<bool>();

    let writer_tx = {
        let state = agent_state.read().await;
        let agent = state
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no agent connected"))?;

        agent.channels.lock().await.insert(channel_id, data_tx);
        agent.pending.lock().await.insert(channel_id, connect_tx);

        agent
            .writer_tx
            .send(Frame::new(Command::Connect, channel_id, target.serialize()))
            .await?;

        agent.writer_tx.clone()
    };

    let connected = tokio::time::timeout(
        tokio::time::Duration::from_secs(30),
        connect_rx,
    )
    .await
    .map_err(|_| anyhow::anyhow!("connect timeout"))?
    .map_err(|_| anyhow::anyhow!("agent dropped"))?;

    if !connected {
        socks5::send_reply(&mut stream, 0x05).await?;
        return Ok(());
    }

    socks5::send_reply(&mut stream, 0x00).await?;
    info!("channel {} → {}:{}", channel_id, target.host, target.port);

    let (mut sock_reader, mut sock_writer) = stream.into_split();
    let writer_tx2 = writer_tx.clone();

    let upstream = tokio::spawn(async move {
        let mut buf = vec![0u8; 32768];
        loop {
            match sock_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if writer_tx
                        .send(Frame::new(Command::Data, channel_id, buf[..n].to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        let _ = writer_tx
            .send(Frame::empty(Command::Close, channel_id))
            .await;
    });

    let downstream = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        while let Some(data) = data_rx.recv().await {
            if sock_writer.write_all(&data).await.is_err() {
                break;
            }
        }
    });

    tokio::select! {
        _ = upstream => {}
        _ = downstream => {}
    }

    let state = agent_state.read().await;
    if let Some(agent) = state.as_ref() {
        agent.channels.lock().await.remove(&channel_id);
        let _ = writer_tx2
            .send(Frame::empty(Command::Close, channel_id))
            .await;
    }

    Ok(())
}
