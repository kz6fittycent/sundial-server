//! Paired hosts: their last status and the commands waiting for them.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use sundial_core::proto::{AdminRequest, AdminResponse};
use sundial_link::{Command, PairCode, expiry, random_hex, sha256_hex, short_fingerprint};
use tokio::sync::Notify;

const PAIR_SECS: i64 = 15 * 60;
const PAIR_TRIES: u32 = 5;
const QUEUE_MAX: usize = 50;
const RESULTS_MAX: usize = 50;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub ts: i64,
    pub id: String,
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Host {
    pub name: String,
    pub version: String,
    /// SHA-256 of the host's random token.
    token_hash: String,
    /// Which computer this is, from hosts that say so.
    machine: Option<String>,
    pub last_seen: i64,
    pub status: Option<AdminResponse>,
    pub queue: Vec<Command>,
    pub results: Vec<CommandResult>,
}

struct Pending {
    secret: String,
    until: i64,
    tries: u32,
}

#[derive(Default)]
struct Inner {
    hosts: BTreeMap<String, Host>,
    pending: Option<Pending>,
    /// Name of the computer that used the last code.
    paired: Option<String>,
    /// Wakes a host's connection: new command, or revoked.
    wake: HashMap<String, Arc<Notify>>,
    /// Newest connection of each host; an older one steps aside.
    online: HashMap<String, u64>,
    conns: u64,
}

pub struct Hub {
    path: PathBuf,
    inner: Mutex<Inner>,
}

/// What became of the last code.
pub enum PairState {
    Waiting(PairCode),
    Done(String),
    None,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostSummary {
    pub id: String,
    pub name: String,
    pub online: bool,
    pub last_seen: i64,
    pub waiting: usize,
    pub results: Vec<CommandResult>,
    pub status: Option<AdminResponse>,
}

impl Hub {
    pub fn load(path: PathBuf) -> Result<Hub> {
        let hosts = match std::fs::read_to_string(&path) {
            Ok(t) => {
                serde_json::from_str(&t).with_context(|| format!("reading {}", path.display()))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Hub {
            path,
            inner: Mutex::new(Inner {
                hosts,
                ..Default::default()
            }),
        })
    }

    fn save(&self, i: &Inner) -> Result<()> {
        use std::io::Write;
        let tmp = self.path.with_extension("tmp");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(serde_json::to_string(&i.hosts)?.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(tmp, &self.path)?;
        Ok(())
    }

    fn save_logged(&self, i: &Inner) {
        if let Err(e) = self.save(i) {
            eprintln!("sundial-server: saving: {e:#}");
        }
    }

    pub fn save_now(&self) {
        self.save_logged(&self.inner.lock().unwrap());
    }

    /// A new one-time code; replaces any earlier one.
    pub fn new_code(&self, self_signed_der: Option<&[u8]>, now: i64) -> PairCode {
        let code = PairCode::new(self_signed_der);
        let mut i = self.inner.lock().unwrap();
        i.paired = None;
        i.pending = Some(Pending {
            secret: code.secret.clone(),
            until: now + PAIR_SECS,
            tries: 0,
        });
        code
    }

    pub fn pair_state(&self, self_signed_der: Option<&[u8]>, now: i64) -> PairState {
        let i = self.inner.lock().unwrap();
        match &i.pending {
            Some(p) if now < p.until && p.tries < PAIR_TRIES => PairState::Waiting(PairCode {
                pin: self_signed_der.map(short_fingerprint),
                secret: p.secret.clone(),
            }),
            Some(_) => PairState::None,
            None => i.paired.clone().map_or(PairState::None, PairState::Done),
        }
    }

    /// Use up the code. Returns the host's id and new token. A computer that was
    /// already paired keeps its entry; its old token stops working.
    pub fn pair(
        &self,
        secret: &str,
        name: &str,
        machine: Option<&str>,
        now: i64,
    ) -> Result<(String, String), String> {
        let mut i = self.inner.lock().unwrap();
        let bad = || "wrong or expired code".to_string();
        let p = i.pending.as_mut().ok_or_else(bad)?;
        if now >= p.until || p.tries >= PAIR_TRIES {
            i.pending = None;
            return Err(bad());
        }
        if sha256_hex(p.secret.as_bytes()) != sha256_hex(secret.as_bytes()) {
            p.tries += 1;
            return Err(bad());
        }
        let machine = machine.and_then(valid_machine);
        let same = machine.as_ref().and_then(|m| {
            let mut all = i.hosts.iter();
            all.find(|(_, h)| h.machine.as_ref() == Some(m))
                .map(|(id, _)| id.clone())
        });
        let (id, token) = (same.unwrap_or_else(|| random_hex(8)), random_hex(32));
        let before = i.hosts.get(&id).cloned();
        let h = i.hosts.entry(id.clone()).or_default();
        h.name = name.chars().filter(|c| !c.is_control()).take(64).collect();
        h.token_hash = sha256_hex(token.as_bytes());
        h.machine = machine;
        if let Err(e) = self.save(&i) {
            match before {
                Some(b) => i.hosts.insert(id, b),
                None => i.hosts.remove(&id),
            };
            eprintln!("sundial-server: saving: {e:#}");
            return Err("the server couldn't save the pairing".into());
        }
        // A connection with the old token ends.
        i.online.remove(&id);
        if let Some(w) = i.wake.get(&id) {
            w.notify_waiters();
        }
        i.pending = None;
        i.paired = i.hosts.get(&id).map(|h| h.name.clone());
        Ok((id, token))
    }

    pub fn check(&self, id: &str, token: &str) -> bool {
        let i = self.inner.lock().unwrap();
        i.hosts
            .get(id)
            .is_some_and(|h| h.token_hash == sha256_hex(token.as_bytes()))
    }

    /// A host connected. Returns the connection number and its wake-up.
    pub fn connected(
        &self,
        id: &str,
        version: &str,
        machine: Option<&str>,
        now: i64,
    ) -> Option<(u64, Arc<Notify>)> {
        let mut i = self.inner.lock().unwrap();
        let h = i.hosts.get_mut(id)?;
        // Paired before hosts said which computer they are.
        if h.machine.is_none() {
            h.machine = machine.and_then(valid_machine);
        }
        h.version = version.chars().take(32).collect();
        h.last_seen = now;
        i.conns += 1;
        let n = i.conns;
        i.online.insert(id.to_string(), n);
        let wake = i.wake.entry(id.to_string()).or_default().clone();
        wake.notify_waiters();
        Some((n, wake))
    }

    /// Still paired, and no newer connection has replaced this one.
    pub fn current(&self, id: &str, conn: u64) -> bool {
        self.inner.lock().unwrap().online.get(id) == Some(&conn)
    }

    pub fn disconnected(&self, id: &str, conn: u64) {
        let mut i = self.inner.lock().unwrap();
        if i.online.get(id) == Some(&conn) {
            i.online.remove(id);
        }
        self.save_logged(&i);
    }

    pub fn status(&self, id: &str, s: AdminResponse, now: i64) {
        let mut i = self.inner.lock().unwrap();
        if let Some(h) = i.hosts.get_mut(id) {
            h.status = Some(s);
            h.last_seen = now;
        }
    }

    /// Commands to send, dropping those that expired.
    pub fn queued(&self, id: &str, now: i64) -> Vec<Command> {
        let mut i = self.inner.lock().unwrap();
        Self::expire(&mut i, now);
        i.hosts.get(id).map(|h| h.queue.clone()).unwrap_or_default()
    }

    fn expire(i: &mut Inner, now: i64) {
        for h in i.hosts.values_mut() {
            let (keep, old): (Vec<_>, Vec<_>) = std::mem::take(&mut h.queue)
                .into_iter()
                .partition(|c| c.expires > now);
            h.queue = keep;
            for c in old {
                push_result(
                    h,
                    now,
                    c.id,
                    false,
                    "expired; the computer was offline".into(),
                );
            }
        }
    }

    pub fn ack(&self, id: &str, cmd: &str, ok: bool, message: String, now: i64) {
        let mut i = self.inner.lock().unwrap();
        if let Some(h) = i.hosts.get_mut(id)
            && h.queue.iter().any(|c| c.id == cmd)
        {
            h.queue.retain(|c| c.id != cmd);
            let message = message.chars().take(500).collect();
            push_result(h, now, cmd.to_string(), ok, message);
        }
        self.save_logged(&i);
    }

    /// True if the computer is online.
    pub fn enqueue(&self, id: &str, req: AdminRequest, now: i64) -> Result<bool, String> {
        let mut i = self.inner.lock().unwrap();
        Self::expire(&mut i, now);
        let h = i.hosts.get_mut(id).ok_or("no such computer")?;
        if h.queue.len() >= QUEUE_MAX {
            return Err("too many commands are waiting for this computer".into());
        }
        let c = Command {
            id: random_hex(16),
            expires: expiry(&req, now),
            req,
        };
        let cid = c.id.clone();
        h.queue.push(c);
        if let Err(e) = self.save(&i) {
            if let Some(h) = i.hosts.get_mut(id) {
                h.queue.retain(|c| c.id != cid);
            }
            return Err(format!("saving: {e:#}"));
        }
        if let Some(w) = i.wake.get(id) {
            w.notify_waiters();
        }
        Ok(i.online.contains_key(id))
    }

    pub fn revoke(&self, id: &str) -> bool {
        let mut i = self.inner.lock().unwrap();
        let had = i.hosts.remove(id).is_some();
        i.online.remove(id);
        if let Some(w) = i.wake.remove(id) {
            w.notify_waiters();
        }
        self.save_logged(&i);
        had
    }

    pub fn list(&self, now: i64) -> Vec<HostSummary> {
        let mut i = self.inner.lock().unwrap();
        Self::expire(&mut i, now);
        i.hosts
            .iter()
            .map(|(id, h)| HostSummary {
                id: id.clone(),
                name: h.name.clone(),
                online: i.online.contains_key(id),
                last_seen: h.last_seen,
                waiting: h.queue.len(),
                results: h.results.clone(),
                status: h.status.clone(),
            })
            .collect()
    }
}

fn valid_machine(m: &str) -> Option<String> {
    (m.len() == 32 && m.bytes().all(|c| c.is_ascii_hexdigit())).then(|| m.to_string())
}

fn push_result(h: &mut Host, ts: i64, id: String, ok: bool, message: String) {
    h.results.push(CommandResult {
        ts,
        id,
        ok,
        message,
    });
    let extra = h.results.len().saturating_sub(RESULTS_MAX);
    h.results.drain(..extra);
}

#[cfg(test)]
mod tests {
    use super::*;
    use sundial_core::rules::Override;

    fn hub(name: &str) -> Hub {
        let p = std::env::temp_dir().join(format!("sundial-hub-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        Hub::load(p).unwrap()
    }

    fn grant() -> AdminRequest {
        AdminRequest::Act {
            user: "kid".into(),
            by: "mom".into(),
            action: Override::Grant { minutes: 30 },
        }
    }

    #[test]
    fn code_works_once_and_expires() {
        let h = hub("code");
        let c = h.new_code(None, 0);
        let (id, tok) = h.pair(&c.secret, "pc", None, 1).unwrap();
        assert!(h.check(&id, &tok) && !h.check(&id, "nope"));
        assert!(h.pair(&c.secret, "pc", None, 2).is_err());
        let c = h.new_code(None, 0);
        assert!(h.pair(&c.secret, "pc", None, PAIR_SECS).is_err());
    }

    #[test]
    fn guessing_kills_the_code() {
        let h = hub("guess");
        let c = h.new_code(None, 0);
        for _ in 0..PAIR_TRIES {
            assert!(h.pair("WRONG", "pc", None, 1).is_err());
        }
        assert!(h.pair(&c.secret, "pc", None, 1).is_err());
    }

    #[test]
    fn queue_survives_restart_and_expires() {
        let h = hub("queue");
        let c = h.new_code(None, 0);
        let (id, _) = h.pair(&c.secret, "pc", None, 0).unwrap();
        h.enqueue(&id, grant(), 0).unwrap();
        let again = Hub::load(h.path.clone()).unwrap();
        assert_eq!(again.queued(&id, 10).len(), 1);
        assert!(again.queued(&id, 1800).is_empty());
        assert!(!again.list(1800)[0].results[0].ok);
    }

    #[test]
    fn revoked_host_is_out() {
        let h = hub("revoke");
        let c = h.new_code(None, 0);
        let (id, tok) = h.pair(&c.secret, "pc", None, 0).unwrap();
        let (n, _) = h.connected(&id, "1", None, 0).unwrap();
        assert!(h.current(&id, n));
        assert!(h.revoke(&id));
        assert!(!h.current(&id, n) && !h.check(&id, &tok));
    }

    #[test]
    fn pairing_again_replaces_the_entry() {
        let h = hub("again");
        let (m, other) = ("a".repeat(32), "b".repeat(32));
        let pair = |m: Option<&str>| {
            let c = h.new_code(None, 0);
            h.pair(&c.secret, "pc", m, 0).unwrap()
        };
        let (id, old) = pair(None);
        let (n, _) = h.connected(&id, "1", Some(&m), 0).unwrap();
        h.enqueue(&id, grant(), 0).unwrap();
        let (same, new) = pair(Some(&m));
        assert_eq!(id, same);
        assert!(!h.current(&id, n) && !h.check(&id, &old) && h.check(&id, &new));
        assert_eq!(h.queued(&id, 1).len(), 1, "waiting changes are kept");
        // The same name is not enough, and neither is a made-up machine.
        assert_ne!(pair(Some(&other)).0, id);
        assert_ne!(pair(None).0, id);
        assert_ne!(pair(Some("junk")).0, pair(Some("junk")).0);
    }
}
