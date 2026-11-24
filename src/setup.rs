//! First-run setup, the Parents section and adding a computer. Setup is open only while
//! there are no parent logins, and only from the home network.

use crate::config::AtHome;
use crate::hub::{Hub, PairState};
use axum::extract::{ConnectInfo, Form, Request, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use chrono::Utc;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use sundial_web::auth::{SESSION_DAYS, hash_password, read_admins, write_admins};
use sundial_web::{App, enc, esc, same_origin, security_headers, shell, signed_in};

const MIN_PASSWORD: usize = 8;
const MAX_PASSWORD: usize = 256;
const MAX_PARENTS: usize = 20;

#[derive(Clone)]
pub struct Setup {
    pub app: App,
    pub hub: Arc<Hub>,
    /// Our certificate, when computers will see it (not behind a proxy).
    pub der: Arc<Option<Vec<u8>>>,
    pub admins: Arc<PathBuf>,
    /// One change to the logins at a time, so first-run can't be won twice.
    pub lock: Arc<Mutex<()>>,
}

pub fn router(s: Setup) -> Router {
    Router::new()
        .route("/setup", get(first).post(create_first))
        .route("/setup/parents", get(parents_step).post(add_parent_step))
        .route("/setup/access", get(access_step))
        .route("/parents", get(parents_page).post(add_parent))
        .route("/parents/password", post(change_password))
        .route("/parents/remove", post(remove_parent))
        .route("/pair", get(pair_page).post(new_pair))
        .with_state(s)
}

/// Until there is a login, the front page is the setup page.
pub async fn first_run(State(s): State<Setup>, req: Request, next: Next) -> Response {
    if matches!(req.uri().path(), "/" | "/login") && !s.app.auth.has_admins() {
        return Redirect::to("/setup").into_response();
    }
    next.run(req).await
}

fn page(title: &str, body: &str) -> Response {
    let html = format!(
        "<header><h1>☀ <span>Sundial</span> <small class=muted>{}</small></h1></header>{body}",
        esc(title)
    );
    let html = shell("Sundial", &html, false).replace("</style>", &format!("{STYLE}</style>"));
    security_headers(Html(html).into_response())
}

const STYLE: &str = "
.field{display:flex;flex-direction:column;gap:4px;margin-top:10px;max-width:360px}
.steps{display:flex;gap:8px;list-style:none;padding:0;margin:0 0 16px;font-size:14px;color:var(--muted);flex-wrap:wrap}
.steps li{padding:2px 12px;border:1px solid var(--line);border-radius:99px}
.steps .on{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600}
a.button{display:inline-block;background:var(--accent);color:#fff;border-radius:10px;padding:9px 14px;font-weight:600;text-decoration:none}
a{color:var(--accent)}.row a{align-self:center}
.pic{display:block;width:100%;max-width:640px;height:auto;margin:12px 0}
.pic rect{fill:var(--bg);stroke:var(--line);stroke-width:1.5}.pic .hot{stroke:var(--accent);stroke-width:2.5}
.pic text{fill:var(--ink);font:600 14px system-ui,sans-serif;text-anchor:middle}.pic .s{fill:var(--muted);font-weight:400;font-size:12px}
.pic path{stroke:var(--accent);stroke-width:2.5;fill:none}.pic .tip{fill:var(--accent);stroke:none}
ol.todo{padding-left:22px}ol.todo li{margin:6px 0}
";

fn steps(on: usize) -> String {
    let mut h = String::from("<ol class=steps>");
    for (i, s) in ["Parents", "Away from home", "Computers"]
        .iter()
        .enumerate()
    {
        let class = if i == on { " class=on" } else { "" };
        h.push_str(&format!("<li{class}>{}. {s}</li>", i + 1));
    }
    h + "</ol>"
}

fn flash(q: &Uri) -> String {
    let find = |k: &str| {
        q.query()
            .unwrap_or("")
            .split('&')
            .find_map(|p| p.strip_prefix(k).and_then(|p| p.strip_prefix('=')))
            .map(decode)
    };
    if let Some(e) = find("err") {
        return format!("<div class='flash err'>{}</div>", esc(&e));
    }
    find("msg")
        .map(|m| format!("<div class=flash>{}</div>", esc(&m)))
        .unwrap_or_default()
}

fn decode(s: &str) -> String {
    let (b, mut out, mut i) = (s.as_bytes(), Vec::new(), 0);
    while i < b.len() {
        let hex = (b[i] == b'%')
            .then(|| s.get(i + 1..i + 3))
            .flatten()
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match hex {
            Some(c) => {
                out.push(c);
                i += 3;
            }
            None => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn login_fields(button: &str) -> String {
    format!(
        "<label class=field>Name <input name=user autocomplete=username autocapitalize=none maxlength=32 required></label>\
         <label class=field>Password (at least {MIN_PASSWORD} characters) <input name=password type=password autocomplete=new-password minlength={MIN_PASSWORD} required></label>\
         <label class=field>Password again <input name=again type=password autocomplete=new-password minlength={MIN_PASSWORD} required></label>\
         <div class=row><button class=primary>{button}</button></div>"
    )
}

#[derive(Deserialize)]
struct NewLogin {
    user: String,
    password: String,
    again: String,
}

fn check_password(p: &str, again: &str) -> Result<(), String> {
    if p != again {
        return Err("The passwords don't match.".into());
    }
    if !(MIN_PASSWORD..=MAX_PASSWORD).contains(&p.chars().count()) {
        return Err(format!("Use at least {MIN_PASSWORD} characters."));
    }
    Ok(())
}

fn check_name(n: &str) -> Result<(), String> {
    let ok = |c: char| c.is_alphanumeric() || "._-".contains(c);
    if n.is_empty() || n.chars().count() > 32 || !n.chars().all(ok) {
        return Err("Use letters, numbers, dots and dashes for the name.".into());
    }
    Ok(())
}

/// Add a login. `first` = only if there are none at all.
fn add(s: &Setup, f: &NewLogin, first: bool) -> Result<String, String> {
    let name = f.user.trim().to_string();
    check_name(&name)?;
    check_password(&f.password, &f.again)?;
    let hash = hash_password(&f.password).map_err(|e| e.to_string())?;
    let _one = s.lock.lock().unwrap();
    let mut a = read_admins(&s.admins);
    if first && !a.is_empty() {
        return Err("Sundial Server is already set up. Sign in.".into());
    }
    if a.contains_key(&name) {
        return Err(format!("There is already a login named {name}."));
    }
    if a.len() >= MAX_PARENTS {
        return Err("There are too many logins.".into());
    }
    a.insert(name.clone(), hash);
    save(&s.admins, &a)?;
    println!("sundial-server: login {name:?} added");
    Ok(name)
}

fn save(path: &Path, a: &std::collections::HashMap<String, String>) -> Result<(), String> {
    write_admins(path, a).map_err(|e| format!("Couldn't save: {e:#}"))
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    // Hashing is slow on purpose.
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or_else(|_| Err("Something went wrong.".into()))
}

async fn first(State(s): State<Setup>, Extension(home): Extension<AtHome>, uri: Uri) -> Response {
    if s.app.auth.has_admins() {
        return Redirect::to("/").into_response();
    }
    if !home.0 {
        return page(
            "Setup",
            "<section class=card><h2>Almost ready</h2><p>Open this page from your home network to set up Sundial Server.</p></section>",
        );
    }
    page(
        "Setup",
        &format!(
            "{}{}<section class=card><h2>Welcome</h2>\
             <p>Make a login for yourself. You'll use it to sign in here. The other parent gets one in a moment.</p>\
             <form method=post action=/setup>{}</form></section>",
            steps(0),
            flash(&uri),
            login_fields("Continue")
        ),
    )
}

async fn create_first(
    State(s): State<Setup>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Extension(home): Extension<AtHome>,
    uri: Uri,
    headers: HeaderMap,
    Form(f): Form<NewLogin>,
) -> Response {
    if !same_origin(&headers, &uri) || !home.0 {
        return StatusCode::FORBIDDEN.into_response();
    }
    if s.app.auth.has_admins() {
        return Redirect::to("/").into_response();
    }
    let s2 = s.clone();
    let made = blocking(move || {
        let name = add(&s2, &f, true)?;
        let now = Utc::now().timestamp();
        Ok(s2.app.auth.login(peer.ip(), &name, &f.password, now))
    })
    .await;
    match made {
        Ok(Some(t)) => {
            let cookie = format!(
                "sundial_session={t}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Strict",
                SESSION_DAYS * 86_400
            );
            (
                [(header::SET_COOKIE, cookie)],
                Redirect::to("/setup/parents"),
            )
                .into_response()
        }
        Ok(None) => Redirect::to("/").into_response(),
        Err(e) => Redirect::to(&format!("/setup?err={}", enc(&e))).into_response(),
    }
}

#[allow(clippy::result_large_err)]
fn parent(s: &Setup, headers: &HeaderMap) -> Result<String, Response> {
    signed_in(&s.app, headers).ok_or_else(|| Redirect::to("/").into_response())
}

/// For forms: also from our own page.
#[allow(clippy::result_large_err)]
fn posting(s: &Setup, headers: &HeaderMap, uri: &Uri) -> Result<String, Response> {
    if !same_origin(headers, uri) {
        return Err(StatusCode::FORBIDDEN.into_response());
    }
    parent(s, headers)
}

fn names(s: &Setup) -> Vec<String> {
    let mut n: Vec<String> = read_admins(&s.admins).into_keys().collect();
    n.sort();
    n
}

async fn parents_step(State(s): State<Setup>, uri: Uri, headers: HeaderMap) -> Response {
    if let Err(r) = parent(&s, &headers) {
        return r;
    }
    page(
        "Setup",
        &format!(
            "{}{}<section class=card><h2>Parents</h2><p>Logins so far: <b>{}</b></p>\
             <div class=row><a class=button href=/setup/access>Continue</a></div>\
             <details class=settings><summary>Add another parent</summary>\
             <form method=post action=/setup/parents>{}</form></details></section>",
            steps(0),
            flash(&uri),
            esc(&names(&s).join(", ")),
            login_fields("Add")
        ),
    )
}

async fn add_parent_step(
    s: State<Setup>,
    uri: Uri,
    headers: HeaderMap,
    f: Form<NewLogin>,
) -> Response {
    add_to(s.0, uri, headers, f.0, "/setup/parents").await
}

async fn add_parent(s: State<Setup>, uri: Uri, headers: HeaderMap, f: Form<NewLogin>) -> Response {
    add_to(s.0, uri, headers, f.0, "/parents").await
}

async fn add_to(s: Setup, uri: Uri, headers: HeaderMap, f: NewLogin, to: &str) -> Response {
    if let Err(r) = posting(&s, &headers, &uri) {
        return r;
    }
    back(
        to,
        blocking(move || add(&s, &f, false).map(|n| format!("{n} can now sign in."))).await,
    )
}

fn back(to: &str, r: Result<String, String>) -> Response {
    let q = match r {
        Ok(m) => format!("msg={}", enc(&m)),
        Err(e) => format!("err={}", enc(&e)),
    };
    Redirect::to(&format!("{to}?{q}")).into_response()
}

const PORT_PICTURE: &str = "<svg class=pic viewBox='0 0 640 150' role=img aria-label='The router sends outside port 8461 to the server'>\
<rect x=10 y=35 width=150 height=80 rx=12></rect><text x=85 y=72>Parent's phone</text><text class=s x=85 y=92>anywhere</text>\
<rect class=hot x=245 y=35 width=150 height=80 rx=12></rect><text x=320 y=72>Your router</text><text class=s x=320 y=92>outside port 8461</text>\
<rect x=480 y=35 width=150 height=80 rx=12></rect><text x=555 y=72>Sundial Server</text><text class=s x=555 y=92>port 8461</text>\
<path d='M160 75H234'></path><path class=tip d='M234 68L246 75L234 82Z'></path><path d='M395 75H469'></path><path class=tip d='M469 68L481 75L469 82Z'></path></svg>";

async fn access_step(State(s): State<Setup>, uri: Uri, headers: HeaderMap) -> Response {
    if let Err(r) = parent(&s, &headers) {
        return r;
    }
    let body = if s.der.is_none() {
        format!(
            "<p>This server is reached through a web proxy at <b>{}</b>. There's nothing to set up here.</p>",
            esc(&reached(&headers, &uri))
        )
    } else {
        format!(
            "<p>At home, everything works now. To use Sundial from anywhere, let your router pass one port to this server:</p>{PORT_PICTURE}\
             <ol class=todo><li>In your router, give this server a fixed address (often called a DHCP reservation).</li>\
             <li>Add a port forward: outside TCP port <b>8461</b> to this server's port <b>8461</b>.</li>\
             <li>Open <b>https://</b> your public address <b>:8461</b> from a phone with Wi-Fi off.</li></ol>\
             <h3>If your address changes</h3><p>Most home addresses change now and then. A dynamic DNS service gives you a name that keeps up: for example \
             <a href='https://www.duckdns.org/install.jsp' target=_blank rel=noreferrer>DuckDNS's instructions</a>. Many routers have one built in.</p>\
             <p class=muted>You can skip this and do it later.</p>"
        )
    };
    page(
        "Setup",
        &format!(
            "{}<section class=card><h2>Away from home</h2>{body}\
             <form method=post action=/pair class=row><input type=hidden name=setup value=1>\
             <button class=primary>Continue</button></form></section>",
            steps(1)
        ),
    )
}

async fn parents_page(State(s): State<Setup>, uri: Uri, headers: HeaderMap) -> Response {
    let me = match parent(&s, &headers) {
        Ok(me) => me,
        Err(r) => return r,
    };
    let mut list = String::new();
    for n in names(&s).iter().filter(|n| **n != me) {
        let n = esc(n);
        list.push_str(&format!(
            "<details><summary>Remove {n}</summary><form method=post action=/parents/remove class=row>\
             <input type=hidden name=user value=\"{n}\"><button class=danger>Remove {n}</button></form></details>"
        ));
    }
    page(
        "Parents",
        &format!(
            "{}<section class=card><h2>Parents</h2><p>{}</p>{list}\
             <details class=settings><summary>Add a parent</summary><form method=post action=/parents>{}</form></details>\
             <details class=settings><summary>Change my password</summary><form method=post action=/parents/password>\
             <label class=field>Current password <input name=current type=password autocomplete=current-password required></label>\
             <label class=field>New password <input name=password type=password autocomplete=new-password minlength={MIN_PASSWORD} required></label>\
             <label class=field>New password again <input name=again type=password autocomplete=new-password minlength={MIN_PASSWORD} required></label>\
             <div class=row><button class=primary>Change</button></div></form></details>\
             <p><a href=/>Back</a></p></section>",
            flash(&uri),
            esc(&names(&s).join(", ")),
            login_fields("Add")
        ),
    )
}

#[derive(Deserialize)]
struct PasswordForm {
    current: String,
    password: String,
    again: String,
}

async fn change_password(
    State(s): State<Setup>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
    Form(f): Form<PasswordForm>,
) -> Response {
    let me = match posting(&s, &headers, &uri) {
        Ok(me) => me,
        Err(r) => return r,
    };
    let r = blocking(move || {
        let now = Utc::now().timestamp();
        if s.app.auth.throttled(peer.ip(), now) {
            return Err("Too many tries. Wait 15 minutes.".into());
        }
        check_password(&f.password, &f.again)?;
        // The same check as signing in, so guesses count toward the lockout.
        let Some(t) = s.app.auth.login(peer.ip(), &me, &f.current, now) else {
            return Err("The current password is wrong.".into());
        };
        s.app.auth.logout(&t);
        let hash = hash_password(&f.password).map_err(|e| e.to_string())?;
        let _one = s.lock.lock().unwrap();
        let mut a = read_admins(&s.admins);
        match a.get_mut(&me) {
            Some(h) => *h = hash,
            None => return Err("That login was removed.".into()),
        }
        save(&s.admins, &a)?;
        Ok("Password changed.".into())
    })
    .await;
    back("/parents", r)
}

#[derive(Deserialize)]
struct NameForm {
    user: String,
}

async fn remove_parent(
    State(s): State<Setup>,
    uri: Uri,
    headers: HeaderMap,
    Form(f): Form<NameForm>,
) -> Response {
    let me = match posting(&s, &headers, &uri) {
        Ok(me) => me,
        Err(r) => return r,
    };
    // Never the last one: that would reopen first-run setup.
    let r = if f.user == me {
        Err("Another parent has to remove your login.".into())
    } else {
        let _one = s.lock.lock().unwrap();
        let mut a = read_admins(&s.admins);
        match a.remove(&f.user) {
            // Both could be removing each other; the one left stays.
            Some(_) if a.contains_key(&me) => {
                save(&s.admins, &a).map(|()| format!("{} was removed.", f.user))
            }
            Some(_) => Err("Your own login was removed.".into()),
            None => Err("There is no such login.".into()),
        }
    };
    back("/parents", r)
}

/// How this page was reached, which is also what a computer should use.
fn address(headers: &HeaderMap) -> String {
    headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("ADDRESS")
        .trim_end_matches(":443")
        .to_string()
}

/// HTTP/2 has the host in the URI instead of a header.
fn reached(headers: &HeaderMap, uri: &Uri) -> String {
    uri.authority()
        .map(|a| a.as_str().trim_end_matches(":443").to_string())
        .unwrap_or_else(|| address(headers))
}

#[derive(Deserialize, Default)]
struct PairForm {
    setup: Option<String>,
}

async fn new_pair(
    State(s): State<Setup>,
    uri: Uri,
    headers: HeaderMap,
    Form(f): Form<PairForm>,
) -> Response {
    if let Err(r) = posting(&s, &headers, &uri) {
        return r;
    }
    s.hub.new_code(s.der.as_deref(), Utc::now().timestamp());
    let to = if f.setup.is_some() {
        "/pair?setup=1"
    } else {
        "/pair"
    };
    Redirect::to(to).into_response()
}

async fn pair_page(State(s): State<Setup>, uri: Uri, headers: HeaderMap) -> Response {
    if let Err(r) = parent(&s, &headers) {
        return r;
    }
    let setup = uri.query() == Some("setup=1");
    let top = if setup { steps(2) } else { String::new() };
    let hidden = if setup {
        "<input type=hidden name=setup value=1>"
    } else {
        ""
    };
    let again = |label: &str| {
        format!(
            "<form method=post action=/pair class=row>{hidden}<button>{label}</button><a href=/>{}</a></form>",
            if setup { "Finish" } else { "Back" }
        )
    };
    let body = match s.hub.pair_state(s.der.as_deref(), Utc::now().timestamp()) {
        PairState::Waiting(code) => format!(
            "<h2>Add a computer</h2><p>On the child's computer, with Sundial installed, run:</p>\
             <p><code>sudo sundial pair {} {code}</code></p><p class=code>{code}</p>\
             <p class=muted>Waiting for the computer. The code works once, for 15 minutes.</p>\
             <div class=row><a href=/>{}</a></div><script>setTimeout(()=>location.reload(),3000)</script>",
            esc(&reached(&headers, &uri)),
            if setup { "Do this later" } else { "Back" }
        ),
        PairState::Done(name) => format!(
            "<h2>{} is connected</h2><p>It appears on the main page within a few seconds.</p>\
             <div class=row><a class=button href=/>Done</a></div>{}",
            esc(&name),
            again("Add another")
        ),
        PairState::None => format!(
            "<h2>Add a computer</h2><p>The code has expired.</p>{}",
            again("New code")
        ),
    };
    page(
        if setup { "Setup" } else { "Computers" },
        &format!("{top}<section class=card>{body}</section>"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_passwords() {
        assert!(check_name("mom").is_ok() && check_name("Zoë.2").is_ok());
        for n in ["", "a:b", "a b", "#x", "a\nb", "<b>"] {
            assert!(check_name(n).is_err(), "{n:?}");
        }
        assert!(check_password("short", "short").is_err());
        assert!(check_password("longenough", "different1").is_err());
        assert!(check_password("longenough", "longenough").is_ok());
    }

    #[test]
    fn decoding() {
        assert_eq!(decode("a%20b%C3%AB%"), "a bë%");
    }
}
