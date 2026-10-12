mod protocol;
mod server;
mod agent;
mod socks5;

use clap::{Parser, Subcommand};

const BANNER: &str = r#"
                           _
  _ __ _____   _____  ___ | | _____
 | '__/ _ \ \ / / __|/ _ \| |/ / __|
 | | |  __/\ V /\__ \ (_) |   <\__ \  ____ ___
 |_|  \___| \_/ |___/\___/|_|\_\___/ |____|___|

 Reverse SOCKS5 proxy - Authorized use only
"#;

#[derive(Parser)]
#[command(name = "revsocks-rs", version, about = "Reverse SOCKS5 proxy for authorized penetration testing")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Run as server: listen for agent + SOCKS5 clients
    Server {
        /// Agent listen address
        #[arg(long, short = 'a', default_value = "0.0.0.0:4443")]
        agent_listen: String,

        /// SOCKS5 listen address
        #[arg(long, short = 's', default_value = "127.0.0.1:1080")]
        socks_listen: String,

        /// Agent authentication password
        #[arg(long, short)]
        password: String,

        /// Require SOCKS5 client authentication
        #[arg(long)]
        socks_auth: bool,

        /// SOCKS5 client password (implies --socks-auth)
        #[arg(long)]
        socks_password: Option<String>,
    },

    /// Run as agent: connect back to server and relay traffic
    Agent {
        /// Server address (host:port)
        #[arg(long, short)]
        connect: String,

        /// Authentication password
        #[arg(long, short)]
        password: String,

        /// Reconnection interval in seconds
        #[arg(long, default_value = "5")]
        retry: u64,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let cli = Cli::parse();
    eprintln!("{}", BANNER);

    match cli.mode {
        Mode::Server {
            agent_listen,
            socks_listen,
            password,
            socks_auth,
            socks_password,
        } => {
            let auth = socks_auth || socks_password.is_some();
            server::run(&agent_listen, &socks_listen, &password, auth, socks_password).await?;
        }
        Mode::Agent {
            connect,
            password,
            retry,
        } => {
            agent::run(&connect, &password, retry).await?;
        }
    }

    Ok(())
}
