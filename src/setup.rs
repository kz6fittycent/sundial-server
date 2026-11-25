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
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use sundial_web::auth::{hash_password, read_admins, write_admins};
use sundial_web::{
    App, enc, esc, same_origin, security_headers, shell, signed_in, signed_in_response, two_factor,
};

const MIN_PASSWORD: usize = 8;
const MAX_PASSWORD: usize = 256;
const MAX_PARENTS: usize = 20;
const ENROLL_SECS: i64 = 15 * 60;

#[derive(Clone)]
pub struct Setup {
    pub app: App,
    pub hub: Arc<Hub>,
    /// Our certificate, when computers will see it (not behind a proxy).
    pub der: Arc<Option<Vec<u8>>>,
    pub admins: Arc<PathBuf>,
    /// One change to the logins at a time, so first-run can't be won twice.
    pub lock: Arc<Mutex<()>>,
    /// parent -> (two-factor secret not confirmed yet, until)
    pub enrolling: Arc<Mutex<HashMap<String, (String, i64)>>>,
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
        .route("/pair/state", get(pair_state))
        .route("/two-factor", get(two_factor_page))
        .route("/two-factor/start", post(two_factor_start))
        .route("/two-factor/on", post(two_factor_on))
        .route("/two-factor/off", post(two_factor_off))
        .with_state(s)
}

/// Until there is a login, the front page is the setup page.
pub async fn first_run(State(s): State<Setup>, req: Request, next: Next) -> Response {
    if matches!(req.uri().path(), "/" | "/login") && !s.app.auth.has_admins() {
        return Redirect::to("/setup").into_response();
    }
    next.run(req).await
}

pub fn page(title: &str, body: &str) -> Response {
    let tab = match title {
        "Computers" => "computers",
        "Parents" | "Two-factor sign-in" => "parents",
        _ => "",
    };
    // Setup has steps instead of tabs.
    let (out, main) = if tab.is_empty() {
        ("", body.to_string())
    } else {
        (
            "<form method=post action=/logout><button>Sign out</button></form>",
            sundial_web::panel(&crate::web::tabs(), tab, "", body),
        )
    };
    let small = if tab.is_empty() { title } else { "Server" };
    let html = format!(
        "<header><h1>☀ <span>Sundial</span> <small class=muted>{}</small></h1>{out}</header>{main}{}",
        esc(small),
        if body.contains("<div class=copy") || body.contains("<div class='copy") {
            COPY_SCRIPT
        } else {
            ""
        }
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
.copy{display:flex;align-items:stretch;gap:8px;margin:8px 0 14px}.copy code{flex:1;min-width:0;background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:10px 12px;font:15px/1.5 ui-monospace,monospace;overflow-wrap:anywhere;white-space:pre-wrap;user-select:all}
.copy button{min-width:124px}.copy.big code{font-size:20px;font-weight:600;letter-spacing:.04em}
@media(max-width:520px){.copy{flex-direction:column}}
.qr{width:220px;max-width:100%;display:block;margin:8px 0 12px;border-radius:8px}.wait-line{display:flex;align-items:center;gap:8px}.wait-line i{width:9px;height:9px;border-radius:50%;background:var(--accent)}
ol.todo{padding-left:22px}ol.todo li{margin:6px 0}
";

/// Text with a Copy button.
fn copy_box(text: &str, button: &str) -> String {
    format!(
        "<div class=copy><code>{}</code><button type=button>{button}</button></div>",
        esc(text)
    )
}

const COPY_SCRIPT: &str = "<script>document.querySelectorAll('.copy button').forEach(b=>b.onclick=async()=>{\
const c=b.previousElementSibling,w=b.textContent;let ok=false;try{await navigator.clipboard.writeText(c.textContent);ok=true}catch(e){\
const r=document.createRange();r.selectNodeContents(c);const s=getSelection();s.removeAllRanges();s.addRange(r);try{ok=document.execCommand('copy')}catch(e){}}\
b.textContent=ok?'Copied':'Press Ctrl+C';setTimeout(()=>b.textContent=w,2000)})</script>";

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
    if let Some(e) = param(q, "err") {
        return format!("<div class='flash err'>{}</div>", esc(&e));
    }
    param(q, "msg")
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

/// `name` = what was typed before, so a mistake doesn't lose it. The field isn't
/// called "username", so browsers don't fill in somebody else's login.
fn login_fields(button: &str, name: &str) -> String {
    format!(
        "<label class=field>Name <input name=user autocomplete=off autocapitalize=none spellcheck=false maxlength=32 value=\"{}\" required></label>\
         <label class=field>Password (at least {MIN_PASSWORD} characters) <input name=password type=password autocomplete=new-password minlength={MIN_PASSWORD} required></label>\
         <label class=field>Password again <input name=again type=password autocomplete=new-password minlength={MIN_PASSWORD} required></label>\
         <div class=row><button class=primary>{button}</button></div>",
        esc(name)
    )
}

fn param(uri: &Uri, key: &str) -> Option<String> {
    uri.query()?
        .split('&')
        .find_map(|p| p.strip_prefix(key)?.strip_prefix('='))
        .map(decode)
}

fn typed(uri: &Uri) -> String {
    param(uri, "name").unwrap_or_default()
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
    two_factor_gone(s, &name)?;
    a.insert(name.clone(), hash);
    save(&s.admins, &a)?;
    println!("sundial-server: login {name:?} added");
    Ok(name)
}

/// A removed login's two-factor must not lock out a new one with its name.
fn two_factor_gone(s: &Setup, name: &str) -> Result<(), String> {
    s.app
        .auth
        .disable_two_factor(name)
        .map(drop)
        .map_err(|e| format!("Couldn't save: {e:#}"))
}

fn save(path: &Path, a: &HashMap<String, String>) -> Result<(), String> {
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
            login_fields("Create my login", &typed(&uri))
        ),
    )
}

async fn create_first(
    State(s): State<Setup>,
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
    let (s2, typed) = (s.clone(), f.user.trim().to_string());
    let made = blocking(move || {
        let name = add(&s2, &f, true)?;
        Ok(s2.app.auth.reopen(&name, Utc::now().timestamp()))
    })
    .await;
    match made {
        Ok(Some(t)) => signed_in_response(&t, "/setup/parents"),
        Ok(None) => Redirect::to("/").into_response(),
        Err(e) => {
            Redirect::to(&format!("/setup?err={}&name={}", enc(&e), enc(&typed))).into_response()
        }
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
    let me = match parent(&s, &headers) {
        Ok(me) => me,
        Err(r) => return r,
    };
    let rows: String = names(&s)
        .iter()
        .map(|n| {
            let you = if *n == me {
                " <span class=pill>you</span>"
            } else {
                ""
            };
            format!("<li><b>{}</b>{you}</li>", esc(n))
        })
        .collect();
    page(
        "Setup",
        &format!(
            "{}{}<section class=card><h2>Parents</h2><p>Your login is <b>{}</b>. You're signed in with it now.</p>\
             <ul class=log>{rows}</ul>\
             <h3>Add another parent</h3><form method=post action=/setup/parents>{}</form>\
             <h3>Done with parents?</h3><div class=row><a class=button href=/setup/access>Continue</a></div></section>",
            steps(0),
            flash(&uri),
            esc(&me),
            login_fields("Add parent", &typed(&uri))
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
    let typed = f.user.trim().to_string();
    match blocking(move || add(&s, &f, false)).await {
        Ok(n) => back(to, Ok(format!("{n} can now sign in."))),
        Err(e) => {
            Redirect::to(&format!("{to}?err={}&name={}", enc(&e), enc(&typed))).into_response()
        }
    }
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
            "{}<section class=card><h2>Parents</h2><p>Signed in as <b>{}</b>. Logins: {}</p>{list}\
             <details class=settings><summary>Add a parent</summary><form method=post action=/parents>{}</form></details>\
             <details class=settings><summary>Change my password</summary><form method=post action=/parents/password>\
             <label class=field>Current password <input name=current type=password autocomplete=current-password required></label>\
             <label class=field>New password <input name=password type=password autocomplete=new-password minlength={MIN_PASSWORD} required></label>\
             <label class=field>New password again <input name=again type=password autocomplete=new-password minlength={MIN_PASSWORD} required></label>\
             <div class=row><button class=primary>Change</button></div></form></details>\
             <p><a href=/two-factor>Two-factor sign-in: {}</a></p></section>",
            flash(&uri),
            esc(&me),
            esc(&names(&s).join(", ")),
            login_fields("Add", &typed(&uri)),
            if s.app.auth.has_two_factor(&me) {
                "on"
            } else {
                "off"
            }
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
        check_password(&f.password, &f.again)?;
        confirm(&s, peer, &me, &f.current)?;
        let hash = hash_password(&f.password).map_err(|e| e.to_string())?;
        let _one = s.lock.lock().unwrap();
        let mut a = read_admins(&s.admins);
        match a.get_mut(&me) {
            Some(h) => *h = hash,
            None => return Err("That login was removed.".into()),
        }
        save(&s.admins, &a)?;
        // Every session with the old password has ended; keep this one going.
        s.app
            .auth
            .reopen(&me, Utc::now().timestamp())
            .ok_or_else(|| "Sign in again.".into())
    })
    .await;
    match r {
        Ok(t) => signed_in_response(
            &t,
            &format!(
                "/parents?msg={}",
                enc("Password changed. Your other devices were signed out.")
            ),
        ),
        Err(e) => back("/parents", Err(e)),
    }
}

/// The password again, before something sensitive.
fn confirm(s: &Setup, peer: SocketAddr, me: &str, pw: &str) -> Result<(), String> {
    let now = Utc::now().timestamp();
    if s.app.auth.throttled(peer.ip(), now) {
        return Err("Too many tries. Wait 15 minutes.".into());
    }
    if !s.app.auth.verify(peer.ip(), me, pw, now) {
        return Err("The current password is wrong.".into());
    }
    Ok(())
}

async fn two_factor_page(State(s): State<Setup>, uri: Uri, headers: HeaderMap) -> Response {
    let me = match parent(&s, &headers) {
        Ok(me) => me,
        Err(r) => return r,
    };
    let (text, button) = if s.app.auth.has_two_factor(&me) {
        (
            "Two-factor sign-in is <b>on</b> for your login. Signing in needs your password and a code.",
            "Turn off",
        )
    } else {
        (
            "Signing in will also need a code from an authenticator app on your phone. It's optional, and only for your login.",
            "Set up",
        )
    };
    let action = if button == "Set up" { "start" } else { "off" };
    page(
        "Two-factor sign-in",
        &format!(
            "{}<section class=card><h2>Two-factor sign-in</h2><p>{text}</p>\
             <form method=post action=/two-factor/{action}>\
             <label class=field>Your password <input name=password type=password autocomplete=current-password required></label>\
             <div class=row><button class=primary>{button}</button><a href=/parents>Back</a></div></form></section>",
            flash(&uri)
        ),
    )
}

#[derive(Deserialize)]
struct Confirm {
    password: String,
}

async fn two_factor_start(
    State(s): State<Setup>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
    Form(f): Form<Confirm>,
) -> Response {
    let me = match posting(&s, &headers, &uri) {
        Ok(me) => me,
        Err(r) => return r,
    };
    let (s2, me2) = (s.clone(), me.clone());
    if let Err(e) = blocking(move || confirm(&s2, peer, &me2, &f.password)).await {
        return back("/two-factor", Err(e));
    }
    // Starting again must not replace the one in use.
    if s.app.auth.has_two_factor(&me) {
        return Redirect::to("/two-factor").into_response();
    }
    let secret = two_factor::new_secret();
    let until = Utc::now().timestamp() + ENROLL_SECS;
    s.enrolling
        .lock()
        .unwrap()
        .insert(me.clone(), (secret.clone(), until));
    enroll_page(&me, &secret, "")
}

fn enroll_page(me: &str, secret: &str, err: &str) -> Response {
    let qr = qr_svg(&two_factor::uri(secret, me));
    let spaced = secret
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    page(
        "Two-factor sign-in",
        &format!(
            "{err}<section class=card><h2>Two-factor sign-in</h2><ol class=todo><li>Scan this with an authenticator app:</li></ol>{qr}\
             <p class=muted>Can't scan it? Type this key:</p>{}\
             <ol class=todo start=2><li>Enter the code the app shows:</li></ol>\
             <form method=post action=/two-factor/on class=row><input name=code inputmode=numeric autocomplete=one-time-code maxlength=10 required>\
             <button class=primary>Turn on</button><a href=/parents>Cancel</a></form></section>",
            copy_box(&spaced, "Copy key")
        ),
    )
}

fn qr_svg(text: &str) -> String {
    let Ok(q) = qrcodegen::QrCode::encode_text(text, qrcodegen::QrCodeEcc::Medium) else {
        return String::new();
    };
    let (n, mut d) = (q.size(), String::new());
    for y in 0..n {
        for x in (0..n).filter(|x| q.get_module(*x, y)) {
            d.push_str(&format!("M{} {}h1v1h-1z", x + 4, y + 4));
        }
    }
    let w = n + 8;
    format!(
        "<svg class=qr viewBox='0 0 {w} {w}' role=img aria-label='QR code'><path fill='#fff' d='M0 0h{w}v{w}h-{w}z'/><path fill='#000' d='{d}'/></svg>"
    )
}

#[derive(Deserialize)]
struct Code {
    code: String,
}

async fn two_factor_on(
    State(s): State<Setup>,
    uri: Uri,
    headers: HeaderMap,
    Form(f): Form<Code>,
) -> Response {
    let me = match posting(&s, &headers, &uri) {
        Ok(me) => me,
        Err(r) => return r,
    };
    let now = Utc::now().timestamp();
    let secret = {
        let mut e = s.enrolling.lock().unwrap();
        e.retain(|_, (_, until)| *until > now);
        e.get(&me).map(|(x, _)| x.clone())
    };
    let Some(secret) = secret else {
        return back(
            "/two-factor",
            Err("That took too long. Start again.".into()),
        );
    };
    match s.app.auth.enable_two_factor(&me, &secret, &f.code, now) {
        Ok(Some(codes)) => {
            s.enrolling.lock().unwrap().remove(&me);
            println!("sundial-server: two-factor on for {me:?}");
            page(
                "Two-factor sign-in",
                &format!(
                    "<section class=card><h2>Two-factor sign-in is on</h2>\
                     <p>Keep these recovery codes somewhere safe. Each one works once, if you lose your phone. They aren't shown again.</p>{}\
                     <div class=row><a class=button href=/parents>Done</a></div></section>",
                    copy_box(&codes.join("\n"), "Copy codes")
                ),
            )
        }
        Ok(None) => enroll_page(
            &me,
            &secret,
            "<div class='flash err'>That code didn't work. Try the next one the app shows.</div>",
        ),
        Err(e) => back("/two-factor", Err(format!("Couldn't save: {e:#}"))),
    }
}

async fn two_factor_off(
    State(s): State<Setup>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
    Form(f): Form<Confirm>,
) -> Response {
    let me = match posting(&s, &headers, &uri) {
        Ok(me) => me,
        Err(r) => return r,
    };
    let r = blocking(move || {
        confirm(&s, peer, &me, &f.password)?;
        two_factor_gone(&s, &me)?;
        println!("sundial-server: two-factor off for {me:?}");
        Ok("Two-factor sign-in is off.".into())
    })
    .await;
    back("/two-factor", r)
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
            Some(_) if a.contains_key(&me) => save(&s.admins, &a)
                .and_then(|()| two_factor_gone(&s, &f.user))
                .map(|()| format!("{} was removed.", f.user)),
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
    let home = if setup { "/" } else { "/?tab=computers" };
    let again = |label: &str| {
        format!(
            "<form method=post action=/pair class=row>{hidden}<button>{label}</button><a href=\"{home}\">{}</a></form>",
            if setup { "Finish" } else { "Back" }
        )
    };
    let body = match s.hub.pair_state(s.der.as_deref(), Utc::now().timestamp()) {
        PairState::Waiting(code) => format!(
            "<h2>Add a computer</h2><ol class=todo><li>On the child's computer, with Sundial installed, open a terminal.</li>\
             <li>Run this command:</li></ol>{}\
             <p class=muted>Or just the pairing code:</p>{}\
             <p class='muted wait-line'><i></i>Waiting for the computer. The code works once, for 15 minutes.</p>\
             <div class=row><a class=plain href=\"{home}\">{}</a></div>\
             <script>setInterval(async()=>{{try{{const r=await fetch('/pair/state');if(r.redirected||(await r.text())!=='waiting')location.reload()}}catch(e){{}}}},3000)</script>",
            copy_box(
                &format!("sudo sundial pair {} {code}", reached(&headers, &uri)),
                "Copy command"
            ),
            copy_box(&code.to_string(), "Copy code").replace("class=copy", "class='copy big'"),
            if setup { "Do this later" } else { "Back" }
        ),
        PairState::Done(name) => format!(
            "<h2>{} is connected</h2><p>It appears under Computers within a few seconds.</p>\
             <div class=row><a class=button href=\"{home}\">Done</a></div>{}",
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

async fn pair_state(State(s): State<Setup>, headers: HeaderMap) -> Response {
    if let Err(r) = parent(&s, &headers) {
        return r;
    }
    let t = match s.hub.pair_state(s.der.as_deref(), Utc::now().timestamp()) {
        PairState::Waiting(_) => "waiting",
        _ => "changed",
    };
    security_headers(t.into_response())
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
