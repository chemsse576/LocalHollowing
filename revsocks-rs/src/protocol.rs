use anyhow::{Result, bail};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};

const MAX_FRAME_SIZE: usize = 1024 * 1024;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Command {
    Connect     = 0x01,
    ConnectOk   = 0x02,
    ConnectFail = 0x03,
    Data        = 0x04,
    Close       = 0x05,
    Ping        = 0x06,
    Pong        = 0x07,
    Auth        = 0x08,
    AuthOk      = 0x09,
    AuthFail    = 0x0A,
}

impl TryFrom<u8> for Command {
    type Error = anyhow::Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(Self::Connect),
            0x02 => Ok(Self::ConnectOk),
            0x03 => Ok(Self::ConnectFail),
            0x04 => Ok(Self::Data),
            0x05 => Ok(Self::Close),
            0x06 => Ok(Self::Ping),
            0x07 => Ok(Self::Pong),
            0x08 => Ok(Self::Auth),
            0x09 => Ok(Self::AuthOk),
            0x0A => Ok(Self::AuthFail),
            _ => bail!("unknown command: 0x{:02X}", v),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub cmd: Command,
    pub channel_id: u32,
    pub data: Vec<u8>,
}

impl Frame {
    pub fn new(cmd: Command, channel_id: u32, data: Vec<u8>) -> Self {
        Self { cmd, channel_id, data }
    }

    pub fn empty(cmd: Command, channel_id: u32) -> Self {
        Self { cmd, channel_id, data: vec![] }
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(&self, w: &mut W) -> Result<()> {
        let mut header = [0u8; 9];
        header[0] = self.cmd as u8;
        header[1..5].copy_from_slice(&self.channel_id.to_be_bytes());
        header[5..9].copy_from_slice(&(self.data.len() as u32).to_be_bytes());
        w.write_all(&header).await?;
        if !self.data.is_empty() {
            w.write_all(&self.data).await?;
        }
        w.flush().await?;
        Ok(())
    }

    pub async fn read_from<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self> {
        let mut header = [0u8; 9];
        r.read_exact(&mut header).await?;
        let cmd = Command::try_from(header[0])?;
        let channel_id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
        if len > MAX_FRAME_SIZE {
            bail!("frame too large: {} bytes", len);
        }
        let mut data = vec![0u8; len];
        if len > 0 {
            r.read_exact(&mut data).await?;
        }
        Ok(Self { cmd, channel_id, data })
    }
}
