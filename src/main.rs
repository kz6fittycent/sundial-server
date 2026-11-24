//! Sundial Server: lets parents manage Sundial computers from anywhere. The computers
//! connect to it; it never connects to them.

mod hub;
mod net;
mod web;

use anyhow::{Context, Result, bail};
use axum::Router;
use axum::routing::get;
use chrono::Utc;
use clap::{Parser, Subcommand};
use hub::{HostSummary, Hub};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use sundial_core::proto::AdminRequest;
use sundial_core::rules::Override;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

#[derive(Parser)]
#[command(
    name = "sundial-server",
    version,
    about = "Parent server for Sundial computers"
)]
struct Cli {
    /// Data directory.
    #[arg(long, default_value_os_t = default_dir())]
    dir: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

fn default_dir() -> PathBuf {
    std::env::var_os("SNAP_COMMON")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/var/lib/sundial-server".into())
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the server.
    Run {
        #[arg(long, default_value = "0.0.0.0:8461")]
        listen: SocketAddr,
    },
    /// Set (or delete) a parent login.
    Passwd {
        name: String,
        #[arg(long)]
        delete: bool,
        /// Read the password from standard input.
        #[arg(long, conflicts_with = "delete")]
        stdin: bool,
    },
    /// Show a one-time code for adding a computer.
    Pair,
    /// List computers and their accounts.
    Hosts,
    /// Remove a computer.
    Revoke { id: String },
    /// Give an account extra minutes.
    Grant {
        id: String,
        user: String,
        minutes: u32,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum Control {
    Pair,
    Hosts,
    Revoke { id: String },
    Send { id: String, req: AdminRequest },
}

#[derive(Default, Serialize, Deserialize)]
struct Reply {
    ok: bool,
    text: String,
    hosts: Vec<HostSummary>,
}

fn now() -> i64 {
    Utc::now().timestamp()
}

#[tokio::main]
async fn main() {
    if let Err(e) = real_main().await {
        eprintln!("sundial-server: {e:#}");
        std::process::exit(2);
    }
}

async fn real_main() -> Result<()> {
    let cli = Cli::parse();
    let sock = cli.dir.join("control.sock");
    let req = match cli.cmd {
        Cmd::Run { listen } => return run(cli.dir, listen).await,
        Cmd::Passwd {
            name,
            delete,
            stdin,
        } => return passwd(&cli.dir.join("admins"), &name, delete, stdin),
        Cmd::Pair => Control::Pair,
        Cmd::Hosts => Control::Hosts,
        Cmd::Revoke { id } => Control::Revoke { id },
        Cmd::Grant { id, user, minutes } => Control::Send {
            id,
            req: AdminRequest::Act {
                user,
                by: "server cli".into(),
                action: Override::Grant { minutes },
            },
        },
    };
    let r = ask(&sock, &req).await?;
    if !r.ok {
        bail!("{}", r.text);
    }
    if !r.text.is_empty() {
        println!("{}", r.text);
    }
    for h in r.hosts {
        let state = if h.online { "online" } else { "offline" };
        println!("{} {} ({state}, {} waiting)", h.id, h.name, h.waiting);
        for u in h.status.iter().flat_map(|s| &s.users) {
            println!("  {}: {}", u.name, u.summary);
            for a in &u.activity_today {
                println!("    {} {} s", a.name, a.secs);
            }
        }
        for c in h.results.iter().rev().take(5) {
            println!("  {} {}", if c.ok { "done:" } else { "failed:" }, c.message);
        }
    }
    Ok(())
}

fn passwd(path: &Path, name: &str, delete: bool, stdin: bool) -> Result<()> {
    use sundial_web::auth;
    if name.is_empty() || name.contains(':') || name.contains(char::is_whitespace) {
        bail!("name can't be empty or contain ':' or spaces");
    }
    let mut admins = auth::read_admins(path);
    if delete {
        if admins.remove(name).is_none() {
            bail!("no login named {name}");
        }
        return auth::write_admins(path, &admins).context("writing logins (run as root)");
    }
    let pw = if stdin {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        line.trim_end_matches(['\r', '\n']).to_string()
    } else {
        rpassword::prompt_password(format!("New password for {name}: "))?
    };
    if pw.chars().count() < 8 {
        bail!("use at least 8 characters");
    }
    if !stdin && rpassword::prompt_password("Again: ")? != pw {
        bail!("passwords don't match");
    }
    admins.insert(name.to_string(), auth::hash_password(&pw)?);
    auth::write_admins(path, &admins).context("writing logins (run as root)")
}

async fn ask(sock: &Path, req: &Control) -> Result<Reply> {
    let mut s = UnixStream::connect(sock)
        .await
        .context("is the server running, and are you root?")?;
    s.write_all(format!("{}\n", serde_json::to_string(req)?).as_bytes())
        .await?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).await?;
    serde_json::from_str(&line).context("bad reply")
}

async fn run(dir: PathBuf, listen: SocketAddr) -> Result<()> {
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let name = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let name = match name.trim() {
        "" => "sundial-server",
        n => n,
    };
    let files = sundial_link::tls::ensure_cert(&dir.join("tls"), name, Vec::new())?;
    let der = sundial_link::tls::cert_der(&files.cert).context("reading the certificate")?;
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&files.cert, &files.key).await?;
    let hub = Arc::new(Hub::load(dir.join("hosts.json"))?);
    let sock = dir.join("control.sock");
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock)?;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
    tokio::spawn(control(listener, hub.clone(), der.clone()));
    let auth = Arc::new(sundial_web::auth::Auth::new(dir.join("admins")));
    let app = Router::new()
        .route("/link", get(net::link))
        .with_state(hub.clone())
        .merge(web::router(hub.clone(), auth, der));
    println!("sundial-server: listening on {listen}");
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        r = axum_server::bind_rustls(listen, tls).serve(app.into_make_service_with_connect_info::<SocketAddr>()) => r.context("listening")?,
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    hub.save_now();
    Ok(())
}

async fn control(listener: UnixListener, hub: Arc<Hub>, der: Vec<u8>) {
    loop {
        let Ok((s, _)) = listener.accept().await else {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            continue;
        };
        let (hub, der) = (hub.clone(), der.clone());
        tokio::spawn(async move {
            let (r, mut w) = s.into_split();
            let mut line = String::new();
            if BufReader::new(r.take(1 << 16))
                .read_line(&mut line)
                .await
                .is_err()
            {
                return;
            }
            let reply = match serde_json::from_str(&line) {
                Ok(c) => handle(&hub, &der, c),
                Err(e) => Reply {
                    text: format!("bad request: {e}"),
                    ..Default::default()
                },
            };
            let mut out = serde_json::to_string(&reply).unwrap_or_default();
            out.push('\n');
            let _ = w.write_all(out.as_bytes()).await;
        });
    }
}

fn handle(hub: &Hub, der: &[u8], c: Control) -> Reply {
    let mut r = Reply {
        ok: true,
        ..Default::default()
    };
    match c {
        Control::Pair => r.text = hub.new_code(Some(der), now()).to_string(),
        Control::Hosts => r.hosts = hub.list(now()),
        Control::Revoke { id } => {
            r.ok = hub.revoke(&id);
            r.text = if r.ok { "removed" } else { "no such computer" }.into();
        }
        Control::Send { id, req } => match hub.enqueue(&id, req, now()) {
            Ok(_) => r.text = "sent (or waiting until it is online)".into(),
            Err(e) => (r.ok, r.text) = (false, e),
        },
    }
    r
}
