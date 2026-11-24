//! The parent page: every paired computer, plus adding and removing computers.

use crate::hub::Hub;
use axum::Router;
use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::post;
use chrono::{Local, Utc};
use serde::Deserialize;
use std::sync::Arc;
use sundial_core::proto::{AdminRequest, AdminResponse};
use sundial_core::rules::fmt_when;
use sundial_web::auth::Auth;
use sundial_web::{
    App, Backend, Section, enc, esc, same_origin, security_headers, shell, signed_in,
};

struct Computers(Arc<Hub>);

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
        for c in self.0.list(Utc::now().timestamp()) {
            h.push_str(&format!(
                "<details><summary>Remove {}</summary><form method=post action=/remove class=row>\
                 <input type=hidden name=id value=\"{}\"><button class=danger>Remove</button></form></details>",
                esc(&c.name),
                esc(&c.id)
            ));
        }
        h.push_str("</section>");
        h
    }
}

#[derive(Clone)]
struct Extra {
    app: App,
    hub: Arc<Hub>,
    der: Arc<Vec<u8>>,
}

pub fn router(hub: Arc<Hub>, auth: Arc<Auth>, der: Vec<u8>) -> Router {
    let app = App {
        backend: Arc::new(Computers(hub.clone())),
        auth,
    };
    let extra = Router::new()
        .route("/pair", post(pair))
        .route("/remove", post(remove))
        .with_state(Extra {
            app: app.clone(),
            hub,
            der: Arc::new(der),
        });
    sundial_web::router(app).merge(extra)
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

async fn pair(State(x): State<Extra>, uri: Uri, headers: HeaderMap) -> Response {
    if let Err(r) = guard(&x, &headers, &uri) {
        return r;
    }
    let code = x.hub.new_code(Some(&x.der), Utc::now().timestamp());
    let body = format!(
        "<div class=card><h1>☀ <span>Add a computer</span></h1>\
         <p>On the child's computer, run this with your server's address:</p>\
         <p><code>sudo sundial pair ADDRESS {code}</code></p>\
         <p class=code>{code}</p>\
         <p class=muted>The code works once, for 15 minutes.</p><p><a href=/>Back</a></p></div>"
    );
    security_headers(Html(shell("Sundial", &body, false)).into_response())
}

#[derive(Deserialize)]
struct RemoveForm {
    id: String,
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
    let q = if x.hub.revoke(&f.id) {
        format!("msg={}", enc("Computer removed."))
    } else {
        format!("err={}", enc("No such computer."))
    };
    Redirect::to(&format!("/?{q}")).into_response()
}
