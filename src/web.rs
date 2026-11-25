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
use sundial_core::places::{MAX_NAME, check_name};
use sundial_core::proto::{AdminRequest, AdminResponse, Location};
use sundial_core::rules::fmt_when;
use sundial_web::auth::Auth;
use sundial_web::{App, Backend, Section, Tab, enc, esc, same_origin, signed_in};

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

    fn tabs(&self) -> Vec<Tab> {
        tabs()
    }

    fn empty(&self) -> String {
        "<h2>No children yet</h2><p>They appear here once a computer with Sundial is connected and manages an account. \
         <a href=\"/?tab=computers\">Computers</a></p>"
            .into()
    }

    fn tab(&self, id: &str) -> Option<String> {
        if id == "location" {
            return Some(self.location());
        }
        if id != "computers" {
            return None;
        }
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
        h.push_str("</section>");
        Some(h)
    }
}

impl Computers {
    fn location(&self) -> String {
        let now = Local::now();
        let mut h = String::new();
        for c in self.0.list(now.timestamp()) {
            h.push_str(&location_card(&c, &now));
        }
        if h.is_empty() {
            h.push_str(
                "<section class=card><h2>Location</h2><p>Add a computer first.</p></section>",
            );
        }
        h
    }
}

fn location_card(c: &HostSummary, now: &DateTime<Local>) -> String {
    let head = format!(
        "<section class=card><h2>{} <span class='pill {}'>{}</span></h2>",
        esc(&c.name),
        if c.online { "ok" } else { "wait" },
        state(c, now)
    );
    let Some(l) = c.status.as_ref().and_then(|s| s.location.as_ref()) else {
        return format!(
            "{head}<p class=muted>Sundial on this computer needs an update before it can show its location.</p></section>"
        );
    };
    let button = |on: &str, class: &str, text: &str| {
        format!(
            "<form method=post action=/location class=row><input type=hidden name=id value=\"{}\">\
             <input type=hidden name=on value={on}><button{class}>{text}</button></form>",
            esc(&c.id)
        )
    };
    if !l.on {
        return format!(
            "{head}<p>Location is off.</p><p class=muted>When it's on, this computer looks up its position every few minutes using \
             the networks around it, and the child sees a notice that it's on. Only the latest position is kept.</p>{}</section>",
            button("1", " class=primary", "Turn on location")
        );
    }
    let fix = match l.fix.filter(|f| f.valid()) {
        Some(f) => format!(
            "<p>Within about {} of {:.4}, {:.4}</p>{}\
             <p class=muted>As of {}.{}</p>\
             <div class=row><a class=plain href=\"https://www.openstreetmap.org/?mlat={:.5}&amp;mlon={:.5}#map={}/{:.5}/{:.5}\" target=_blank rel=noreferrer>Show on a map</a></div>",
            distance(f.accuracy_m),
            f.lat,
            f.lon,
            if f.accuracy_m > ROUGH_METERS {
                "<p class='flash err'>This is only a rough area. It's often the internet provider's location, not the computer's.</p>"
            } else {
                ""
            },
            fmt_when(f.at, now),
            if c.online {
                ""
            } else {
                " It's offline now, so it may have moved."
            },
            f.lat,
            f.lon,
            if f.accuracy_m > ROUGH_METERS { 10 } else { 16 },
            f.lat,
            f.lon
        ),
        None if l.problem.is_some() => String::new(),
        None => "<p>Looking for a position. The first position can take a minute.</p>".into(),
    };
    let problem = l
        .problem
        .as_ref()
        .map(|p| {
            format!(
                "<p class='flash err'>The last try didn't work: {}</p>",
                esc(p)
            )
        })
        .unwrap_or_default();
    // A refused mark (no Wi-Fi in range, say) comes back as the computer's last result.
    let refused = c
        .results
        .last()
        .filter(|r| !r.ok && now.timestamp() - r.ts < STALE_SECS)
        .map(|r| format!("<p class='flash err'>{}</p>", esc(&r.message)))
        .unwrap_or_default();
    format!(
        "{head}{refused}{}{fix}{problem}{}{}</section>",
        at_place(l, c, now),
        places_form(l, c),
        button("0", "", "Turn off location")
    )
}

/// "At Home", or that it's somewhere else.
fn at_place(l: &Location, c: &HostSummary, now: &DateTime<Local>) -> String {
    let (Some(names), Some(at)) = (&l.places, l.looked) else {
        return String::new();
    };
    if names.is_empty() {
        return String::new();
    }
    let was = !c.online || now.timestamp() - at > STALE_SECS;
    let text = match (&l.place, was) {
        (Some(p), false) => format!("At {}", esc(p)),
        (Some(p), true) => format!("Last seen at {}", esc(p)),
        (None, false) => "Not at a place you've marked".into(),
        (None, true) => "Last seen away from the places you've marked".into(),
    };
    format!(
        "<p class=big><b>{text}</b> <span class=muted>as of {}</span></p>",
        fmt_when(at, now)
    )
}

fn places_form(l: &Location, c: &HostSummary) -> String {
    let Some(names) = &l.places else {
        return "<p class=muted>Update Sundial on this computer to mark places such as Home.</p>"
            .into();
    };
    let id = esc(&c.id);
    let mut h = String::from("<h3>Places</h3>");
    if c.online {
        h.push_str(&format!(
            "<form method=post action=/place class=row><input type=hidden name=id value=\"{id}\">\
             <label for=place-{id}>The computer is now at</label>\
             <input id=place-{id} name=name maxlength={MAX_NAME} placeholder=Home autocomplete=off required>\
             <button class=primary>Mark this place</button></form>\
             <p class=muted>Sundial recognizes it later by the Wi-Fi networks around it. Mark a big place again from another room to help.</p>"
        ));
    } else {
        h.push_str("<p class=muted>A place can be marked when this computer is online.</p>");
    }
    for n in names {
        h.push_str(&format!(
            "<form method=post action=/place/remove class=row><input type=hidden name=id value=\"{id}\">\
             <input type=hidden name=name value=\"{0}\"><b>{0}</b><button>Remove</button></form>",
            esc(n)
        ));
    }
    h
}

const STALE_SECS: i64 = 300;
const ROUGH_METERS: f64 = 3000.0;

fn distance(m: f64) -> String {
    if m < 1000.0 {
        format!("{} m", ((m / 10.0).ceil() * 10.0).max(10.0))
    } else {
        format!("{} km", (m / 1000.0).round())
    }
}

pub fn tabs() -> Vec<Tab> {
    vec![
        Tab {
            id: "location",
            label: "Location",
            href: "/?tab=location",
        },
        Tab {
            id: "parents",
            label: "Parents",
            href: "/parents",
        },
        Tab {
            id: "computers",
            label: "Computers",
            href: "/?tab=computers",
        },
    ]
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
        .route("/location", post(location))
        .route("/place", post(add_place))
        .route("/place/remove", post(remove_place))
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
fn guard(x: &Extra, headers: &HeaderMap, uri: &Uri) -> Result<String, Response> {
    if !same_origin(headers, uri) {
        return Err(StatusCode::FORBIDDEN.into_response());
    }
    match signed_in(&x.app, headers) {
        Some(p) => Ok(p),
        None => Err(Redirect::to("/").into_response()),
    }
}

#[derive(Deserialize)]
struct RemoveForm {
    id: String,
    confirm: Option<String>,
}

async fn location(
    State(x): State<Extra>,
    uri: Uri,
    headers: HeaderMap,
    Form(f): Form<LocationForm>,
) -> Response {
    let by = match guard(&x, &headers, &uri) {
        Ok(by) => by,
        Err(r) => return r,
    };
    let now = Utc::now().timestamp();
    // Hosts that don't know the request would drop the connection over it.
    let known = x
        .hub
        .list(now)
        .into_iter()
        .find(|c| c.id == f.id)
        .is_some_and(|c| c.status.is_some_and(|s| s.location.is_some()));
    let r = if known {
        let on = f.on == "1";
        x.hub
            .enqueue(&f.id, AdminRequest::SetLocation { by, on }, now)
    } else {
        Err("This computer can't show its location.".into())
    };
    let q = match r {
        Ok(true) => format!("msg={}", enc("Sent. It takes a few seconds.")),
        Ok(false) => format!("msg={}", enc("Waiting; this computer is offline.")),
        Err(e) => format!("err={}", enc(&e)),
    };
    Redirect::to(&format!("/?tab=location&{q}")).into_response()
}

#[derive(Deserialize)]
struct PlaceForm {
    id: String,
    name: String,
}

async fn add_place(
    State(x): State<Extra>,
    uri: Uri,
    headers: HeaderMap,
    Form(f): Form<PlaceForm>,
) -> Response {
    place(&x, &headers, &uri, &f, true)
}

async fn remove_place(
    State(x): State<Extra>,
    uri: Uri,
    headers: HeaderMap,
    Form(f): Form<PlaceForm>,
) -> Response {
    place(&x, &headers, &uri, &f, false)
}

fn place(x: &Extra, headers: &HeaderMap, uri: &Uri, f: &PlaceForm, add: bool) -> Response {
    let by = match guard(x, headers, uri) {
        Ok(by) => by,
        Err(r) => return r,
    };
    let now = Utc::now().timestamp();
    let host = x.hub.list(now).into_iter().find(|c| c.id == f.id);
    // Hosts that don't know the request would drop the connection over it.
    let able = host.as_ref().is_some_and(|c| {
        c.status
            .as_ref()
            .and_then(|s| s.location.as_ref())
            .is_some_and(|l| l.places.is_some())
    });
    let r = if !able {
        Err("This computer can't mark places.".into())
    } else if add && !host.is_some_and(|c| c.online) {
        Err("This computer is offline, so it can't tell where it is.".into())
    } else if add {
        check_name(&f.name).and_then(|name| {
            x.hub
                .enqueue(&f.id, AdminRequest::AddPlace { by, name }, now)
        })
    } else {
        let name = f.name.clone();
        x.hub
            .enqueue(&f.id, AdminRequest::RemovePlace { by, name }, now)
    };
    let q = match r {
        Ok(true) => format!("msg={}", enc("Sent. It takes a few seconds.")),
        Ok(false) => format!("msg={}", enc("Waiting; this computer is offline.")),
        Err(e) => format!("err={}", enc(&e)),
    };
    Redirect::to(&format!("/?tab=location&{q}")).into_response()
}

#[derive(Deserialize)]
struct LocationForm {
    id: String,
    on: String,
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
                 <button class=danger>Remove</button><a class=plain href=\"/?tab=computers\">Keep it</a></form></section>",
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
    Redirect::to(&format!("/?tab=computers&{q}")).into_response()
}
