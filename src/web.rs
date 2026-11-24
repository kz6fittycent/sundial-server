//! The parent page: every paired computer, plus adding and removing computers.

use crate::hub::{HostSummary, Hub};
use crate::setup::{self, Setup};
use axum::Router;
use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::post;
use chrono::{DateTime, Local, Utc};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use sundial_core::proto::{AdminRequest, AdminResponse};
use sundial_core::rules::fmt_when;
use sundial_web::auth::Auth;
use sundial_web::{App, Backend, Section, enc, esc, same_origin, signed_in};

struct Computers(Arc<Hub>);

fn state(c: &HostSummary, now: &DateTime<Local>) -> String {
    match (c.online, c.last_seen) {
        (true, _) => "online".into(),
        (false, 0) => "never connected".into(),
        (false, t) => format!("offline since {}", fmt_when(t, now)),
    }
}

impl Backend for Computers {
    fn subtitle(&self) -> String {
        "Server".into()
    }

    fn sections(&self) -> Vec<Section> {
        let now = Local::now();
        self.0
            .list(now.timestamp())
            .into_iter()
            .map(|h| {
                let mut note = match (h.online, h.last_seen) {
                    (true, _) => "Online".to_string(),
                    (false, 0) => "Not connected yet".into(),
                    (false, t) => {
                        format!(
                            "Offline. Shown as of {}; its limits still apply.",
                            fmt_when(t, &now)
                        )
                    }
                };
                if h.waiting > 0 {
                    note.push_str(&format!(" {} change(s) waiting.", h.waiting));
                }
                if let Some(r) = h.results.last().filter(|r| !r.ok) {
                    note.push_str(&format!(
                        " Last change failed ({}): {}",
                        fmt_when(r.ts, &now),
                        r.message
                    ));
                }
                Section {
                    key: h.id,
                    title: Some(h.name),
                    note: Some(note),
                    status: h.status.unwrap_or_else(AdminResponse::default),
                }
            })
            .collect()
    }

    fn handle(&self, key: &str, req: AdminRequest) -> Result<String, String> {
        let online = self.0.enqueue(key, req, Utc::now().timestamp())?;
        Ok(if online {
            "sent"
        } else {
            "waiting; this computer is offline"
        }
        .into())
    }

    fn passwd_command(&self) -> &'static str {
        "sudo sundial-server passwd NAME"
    }

    fn extra(&self) -> String {
        let mut h = String::from(
            "<section class=card><h2>Computers</h2><form method=post action=/pair class=row>\
             <button class=primary>Add a computer</button></form>",
        );
        let now = Local::now();
        for c in self.0.list(now.timestamp()) {
            h.push_str(&format!(
                "<form method=post action=/remove class=row><input type=hidden name=id value=\"{}\">\
                 <b>{}</b><span class='pill {}'>{}</span><button>Remove...</button></form>",
                esc(&c.id),
                esc(&c.name),
                if c.online { "ok" } else { "wait" },
                state(&c, &now)
            ));
        }
        h.push_str("</section><section class=card><h2>Parents</h2><p><a href=/parents>Logins and passwords</a></p></section>");
        h
    }
}

#[derive(Clone)]
struct Extra {
    app: App,
    hub: Arc<Hub>,
}

pub fn router(hub: Arc<Hub>, auth: Arc<Auth>, admins: PathBuf, der: Option<Vec<u8>>) -> Router {
    let app = App {
        backend: Arc::new(Computers(hub.clone())),
        auth,
    };
    let extra = Router::new()
        .route("/remove", post(remove))
        .with_state(Extra {
            app: app.clone(),
            hub: hub.clone(),
        });
    let s = Setup {
        app: app.clone(),
        hub,
        der: Arc::new(der),
        admins: Arc::new(admins),
        lock: Arc::default(),
        enrolling: Arc::default(),
    };
    sundial_web::router(app)
        .merge(extra)
        .merge(setup::router(s.clone()))
        .layer(axum::middleware::from_fn_with_state(s, setup::first_run))
}

#[allow(clippy::result_large_err)]
fn guard(x: &Extra, headers: &HeaderMap, uri: &Uri) -> Result<(), Response> {
    if !same_origin(headers, uri) {
        return Err(StatusCode::FORBIDDEN.into_response());
    }
    match signed_in(&x.app, headers) {
        Some(_) => Ok(()),
        None => Err(Redirect::to("/").into_response()),
    }
}

#[derive(Deserialize)]
struct RemoveForm {
    id: String,
    confirm: Option<String>,
}

async fn remove(
    State(x): State<Extra>,
    uri: Uri,
    headers: HeaderMap,
    Form(f): Form<RemoveForm>,
) -> Response {
    if let Err(r) = guard(&x, &headers, &uri) {
        return r;
    }
    let now = Local::now();
    let known = x
        .hub
        .list(now.timestamp())
        .into_iter()
        .find(|c| c.id == f.id);
    if let Some(c) = known.filter(|_| f.confirm.is_none()) {
        let warn = if c.online {
            "It's connected now. Until you pair it again, you won't see it here or be able to change anything on it."
        } else {
            "It isn't connected now. If it's still in use, it needs pairing again."
        };
        return setup::page(
            "Computers",
            &format!(
                "<section class=card><h2>Remove {}? <span class='pill {}'>{}</span></h2><p>{warn} Its limits stay in force.</p>\
                 <form method=post action=/remove class=row><input type=hidden name=id value=\"{}\"><input type=hidden name=confirm value=1>\
                 <button class=danger>Remove</button><a class=plain href=/>Keep it</a></form></section>",
                esc(&c.name),
                if c.online { "ok" } else { "wait" },
                state(&c, &now),
                esc(&c.id)
            ),
        );
    }
    let q = if x.hub.revoke(&f.id) {
        format!("msg={}", enc("Computer removed."))
    } else {
        format!("err={}", enc("No such computer."))
    };
    Redirect::to(&format!("/?{q}")).into_response()
}
