//! `/link`: where hosts connect.

use crate::hub::Hub;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use chrono::Utc;
use std::sync::Arc;
use std::time::Duration;
use sundial_link::{Auth, HostMsg, MAX_MESSAGE, PROTO, ServerMsg};

const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const PING_EVERY: Duration = Duration::from_secs(20);
const DEAD_AFTER: Duration = Duration::from_secs(60);
/// Before signing in, a host has no reason to send more than a short hello.
const HELLO_MAX: usize = 4096;

pub async fn link(State(hub): State<Arc<Hub>>, up: WebSocketUpgrade) -> Response {
    up.max_message_size(MAX_MESSAGE)
        .max_frame_size(MAX_MESSAGE)
        .on_upgrade(move |ws| serve(hub, ws))
}

fn now() -> i64 {
    Utc::now().timestamp()
}

async fn send(ws: &mut WebSocket, m: &ServerMsg) -> bool {
    match serde_json::to_string(m) {
        Ok(t) => ws.send(Message::Text(t.into())).await.is_ok(),
        Err(_) => false,
    }
}

async fn refuse(mut ws: WebSocket, reason: impl Into<String>) {
    let reason = reason.into();
    send(&mut ws, &ServerMsg::Refused { reason }).await;
    let _ = ws.send(Message::Close(None)).await;
}

async fn serve(hub: Arc<Hub>, mut ws: WebSocket) {
    let first = tokio::time::timeout(HELLO_TIMEOUT, ws.recv()).await;
    let Ok(Some(Ok(Message::Text(t)))) = first else {
        return;
    };
    if t.len() > HELLO_MAX {
        return;
    }
    let Ok(HostMsg::Hello {
        proto,
        name,
        version,
        auth,
    }) = serde_json::from_str(&t)
    else {
        return;
    };
    if proto != PROTO {
        return refuse(
            ws,
            "update Sundial and Sundial Server; their versions don't match",
        )
        .await;
    }
    match auth {
        Auth::Pair { secret } => match hub.pair(&secret, &name, now()) {
            Ok((host_id, token)) => {
                println!("sundial-server: paired {name:?}");
                let token = Some(token);
                send(&mut ws, &ServerMsg::Welcome { host_id, token }).await;
                let _ = ws.send(Message::Close(None)).await;
            }
            Err(e) => refuse(ws, e).await,
        },
        Auth::Token { host_id, token } => {
            if !hub.check(&host_id, &token) {
                return refuse(ws, "this computer is no longer paired").await;
            }
            let Some((conn, wake)) = hub.connected(&host_id, &version, now()) else {
                return;
            };
            let welcome = ServerMsg::Welcome {
                host_id: host_id.clone(),
                token: None,
            };
            if send(&mut ws, &welcome).await {
                session(&hub, &mut ws, &host_id, conn, &wake).await;
            }
            hub.disconnected(&host_id, conn);
        }
    }
}

async fn session(hub: &Hub, ws: &mut WebSocket, id: &str, conn: u64, wake: &tokio::sync::Notify) {
    // Commands already sent on this connection; unanswered ones go again on the next.
    let mut sent: Vec<String> = Vec::new();
    let mut heard = tokio::time::Instant::now();
    let mut ping = tokio::time::interval(PING_EVERY);
    loop {
        // Registered before the queue is read, so a command added meanwhile isn't missed.
        let woken = wake.notified();
        tokio::pin!(woken);
        woken.as_mut().enable();
        if !hub.current(id, conn) {
            return;
        }
        for c in hub.queued(id, now()) {
            if !sent.contains(&c.id) {
                sent.push(c.id.clone());
                if !send(ws, &ServerMsg::Command(c)).await {
                    return;
                }
            }
        }
        tokio::select! {
            _ = woken => {}
            _ = ping.tick() => {
                if heard.elapsed() > DEAD_AFTER
                    || ws.send(Message::Ping(Vec::new().into())).await.is_err()
                {
                    return;
                }
            }
            m = ws.recv() => {
                let Some(Ok(m)) = m else { return };
                heard = tokio::time::Instant::now();
                match m {
                    Message::Text(t) => match serde_json::from_str(&t) {
                        Ok(HostMsg::Status { status }) => hub.status(id, *status, now()),
                        Ok(HostMsg::Ack { id: cmd, ok, message }) => {
                            hub.ack(id, &cmd, ok, message, now());
                            sent.retain(|s| *s != cmd);
                        }
                        _ => return,
                    },
                    Message::Close(_) => return,
                    _ => {}
                }
            }
        }
    }
}
