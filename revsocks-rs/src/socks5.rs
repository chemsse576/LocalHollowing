use anyhow::{Result, bail};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl Target {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + self.host.len() + 2);
        let host = self.host.as_bytes();
        buf.push(host.len() as u8);
        buf.extend_from_slice(host);
        buf.extend_from_slice(&self.port.to_be_bytes());
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            bail!("empty target data");
        }
        let host_len = data[0] as usize;
        if data.len() < 1 + host_len + 2 {
            bail!("target data truncated");
        }
        let host = String::from_utf8(data[1..1 + host_len].to_vec())?;
        let port = u16::from_be_bytes([data[1 + host_len], data[2 + host_len]]);
        Ok(Self { host, port })
    }

    pub fn addr_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    require_auth: bool,
    password: Option<&str>,
) -> Result<Target> {
    let ver = stream.read_u8().await?;
    if ver != 0x05 {
        bail!("not SOCKS5 (version {})", ver);
    }

    let nmethods = stream.read_u8().await?;
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;

    if require_auth {
        if !methods.contains(&0x02) {
            stream.write_all(&[0x05, 0xFF]).await?;
            bail!("client doesn't support username/password auth");
        }
        stream.write_all(&[0x05, 0x02]).await?;

        let auth_ver = stream.read_u8().await?;
        if auth_ver != 0x01 {
            bail!("bad auth sub-negotiation version: {}", auth_ver);
        }
        let ulen = stream.read_u8().await? as usize;
        let mut _username = vec![0u8; ulen];
        stream.read_exact(&mut _username).await?;
        let plen = stream.read_u8().await? as usize;
        let mut pass_buf = vec![0u8; plen];
        stream.read_exact(&mut pass_buf).await?;

        if let Some(expected) = password {
            if String::from_utf8_lossy(&pass_buf) != expected {
                stream.write_all(&[0x01, 0x01]).await?;
                bail!("SOCKS5 auth failed");
            }
        }
        stream.write_all(&[0x01, 0x00]).await?;
    } else {
        stream.write_all(&[0x05, 0x00]).await?;
    }

    let ver = stream.read_u8().await?;
    let cmd = stream.read_u8().await?;
    let _rsv = stream.read_u8().await?;
    let atyp = stream.read_u8().await?;

    if ver != 0x05 {
        bail!("bad SOCKS5 request version: {}", ver);
    }
    if cmd != 0x01 {
        send_reply(stream, 0x07).await?;
        bail!("unsupported command: {} (only CONNECT)", cmd);
    }

    let host = match atyp {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            Ipv4Addr::from(addr).to_string()
        }
        0x03 => {
            let len = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain)?
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            format!("[{}]", Ipv6Addr::from(addr))
        }
        _ => {
            send_reply(stream, 0x08).await?;
            bail!("unsupported address type: 0x{:02X}", atyp);
        }
    };

    let port = stream.read_u16().await?;
    Ok(Target { host, port })
}

pub async fn send_reply<W: AsyncWrite + Unpin>(w: &mut W, status: u8) -> Result<()> {
    w.write_all(&[
        0x05, status, 0x00,
        0x01,             // IPv4
        0, 0, 0, 0,      // 0.0.0.0
        0, 0,             // port 0
    ]).await?;
    Ok(())
}
