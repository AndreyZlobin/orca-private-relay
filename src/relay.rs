//! Wire-compatible director + single relay cell. Payloads are opaque E2EE frames.
use super::*;
use axum::{
    extract::{
        Path, State, WebSocketUpgrade,
        ws::{CloseFrame, Message, WebSocket},
    },
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use base64::engine::general_purpose::STANDARD;
use crypto_box::{
    PublicKey, SalsaBox, SecretKey,
    aead::{Aead, AeadCore, OsRng},
};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use std::time::Duration;
use tokio::sync::{Notify, mpsc, oneshot};

#[derive(Clone, Serialize, Deserialize)]
pub struct Device {
    host: String,
    id: String,
    current: String,
    expires: u64,
    version: u64,
    grace: Option<String>,
    grace_expires: u64,
}
#[derive(Clone)]
pub struct Host {
    pub tx: mpsc::Sender<Value>,
    generation: u64,
    cancel: Arc<Notify>,
}
pub struct Invite {
    host: String,
    device: String,
    expires: u64,
    attempts: u8,
}
pub struct Link {
    host: String,
    device: String,
    ticket: String,
    generation: u64,
    kind: String,
    expires: u64,
    accepted_hash: String,
    attached: bool,
    socket: Option<oneshot::Sender<WebSocket>>,
}
fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
fn valid_token(s: &str) -> bool {
    s.len() == 43 && URL_SAFE_NO_PAD.decode(s).is_ok_and(|v| v.len() == 32)
}
fn device_key(host: &str, device: &str) -> String {
    format!("{host}:{device}")
}
fn claim(s: &Server, h: &HeaderMap) -> Result<auth::Claims, (StatusCode, Json<Value>)> {
    auth::verify(s, auth::bearer(h).ok_or_else(denied)?).ok_or_else(denied)
}

pub async fn assign(State(s): State<App>, h: HeaderMap, Json(v): Json<Value>) -> ApiResult {
    let c = claim(&s, &h)?;
    if text(&v, "relayHostId")? != c.host || v["v"] != 1 {
        return Err(bad("invalid_assignment"));
    }
    let mut db = s.store.lock().unwrap();
    let epoch = db
        .update(|d| {
            let e = d.epochs.entry(c.host.clone()).or_insert(0);
            *e += 1;
            *e
        })
        .map_err(|_| db_error())?;
    Ok(Json(
        json!({"v":1,"cellUrl":s.origin,"assignmentEpoch":epoch,"lease":auth::sign(&s,&c)}),
    ))
}
fn lookup_device(s: &Server, host: &str, token: &str) -> Option<(Device, String)> {
    if !valid_token(token) {
        return None;
    }
    let hash = hash(token);
    let db = s.store.lock().unwrap();
    db.data.devices.values().find_map(|d| {
        if d.host != host {
            return None;
        }
        if d.expires > now() && same(&d.current, &hash) {
            Some((d.clone(), "current".into()))
        } else if d.expires > now()
            && d.grace_expires > now()
            && d.grace.as_deref().is_some_and(|h| same(h, &hash))
        {
            Some((d.clone(), "grace".into()))
        } else {
            None
        }
    })
}
pub async fn resolve(State(s): State<App>, Json(v): Json<Value>) -> ApiResult {
    let host = text(&v, "relayHostId")?;
    let token = text(&v, "resumeToken")?;
    if v["v"] != 1 || lookup_device(&s, host, token).is_none() {
        return Err(denied());
    }
    let epoch = s
        .store
        .lock()
        .unwrap()
        .data
        .epochs
        .get(host)
        .copied()
        .ok_or_else(denied)?;
    Ok(Json(
        json!({"v":1,"cellUrl":s.origin,"assignmentEpoch":epoch,"leaseExpiresAt":now()+HOUR}),
    ))
}
fn limited(s: &App) -> Result<tokio::sync::OwnedSemaphorePermit, (StatusCode, Json<Value>)> {
    s.sockets
        .clone()
        .try_acquire_owned()
        .map_err(|_| fail(StatusCode::TOO_MANY_REQUESTS, "connection_limit"))
}
pub async fn control_upgrade(
    State(s): State<App>,
    h: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, (StatusCode, Json<Value>)> {
    let c = claim(&s, &h)?;
    let permit = limited(&s)?;
    Ok(ws
        .max_message_size(64 * 1024)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            if let Err(e) = control(s, socket, c).await {
                eprintln!("control ended: {e}")
            }
        })
        .into_response())
}
async fn send(socket: &mut WebSocket, v: Value) -> anyhow::Result<()> {
    socket.send(Message::Text(v.to_string().into())).await?;
    Ok(())
}
async fn read_json(socket: &mut WebSocket) -> anyhow::Result<Value> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match socket.recv().await {
                Some(Ok(Message::Text(v))) => return Ok(serde_json::from_str(&v)?),
                Some(Ok(Message::Ping(v))) => {
                    socket.send(Message::Pong(v)).await?;
                }
                _ => anyhow::bail!("expected JSON"),
            }
        }
    })
    .await?
}
fn field(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    out.extend_from_slice(&(name.len() as u32).to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value)
}
fn challenge(
    s: &Server,
    c: &auth::Claims,
    hello: &Value,
) -> anyhow::Result<(Value, Vec<u8>, Vec<u8>)> {
    let raw = STANDARD.decode(&c.key)?;
    let key: [u8; 32] = raw
        .clone()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid key"))?;
    let secret = SecretKey::generate(&mut OsRng);
    let public = secret.public_key();
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let challenge_id = random();
    let issued = now();
    let expires = issued + 10_000;
    let epoch = hello["assignmentEpoch"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("no epoch"))?;
    let mut t = Vec::new();
    for (name, value) in [
        ("protocol", b"orca-relay-host-proof/v1".as_slice()),
        ("version", &[1]),
        ("relayOrigin", s.origin.as_bytes()),
        ("relayEphemeralPublicKey", public.as_bytes()),
        ("challengeNonce", nonce.as_slice()),
        ("challengeId", challenge_id.as_bytes()),
        ("issuedAt", &issued.to_be_bytes()),
        ("expiresAt", &expires.to_be_bytes()),
        ("userId", c.user.as_bytes()),
        ("profileId", c.profile.as_bytes()),
        ("organizationId", b""),
        ("relayHostId", c.host.as_bytes()),
        ("hostPublicKey", &raw),
        ("assignmentEpoch", &epoch.to_be_bytes()),
        (
            "previousGeneration",
            &hello["previousGeneration"]
                .as_u64()
                .map(|v| v.to_be_bytes().to_vec())
                .unwrap_or_default(),
        ),
        (
            "resumeRequested",
            &[u8::from(
                hello["controlResumeSecret"]
                    .as_str()
                    .is_some_and(|v| !v.is_empty()),
            )],
        ),
    ] {
        field(&mut t, name, value)
    }
    let mut proof_secret = vec![0; 32];
    rand::thread_rng().fill_bytes(&mut proof_secret);
    let mut plaintext = b"orca-relay-host-challenge/v1\0".to_vec();
    plaintext.extend_from_slice(&(t.len() as u32).to_be_bytes());
    plaintext.extend_from_slice(&t);
    plaintext.extend_from_slice(&proof_secret);
    let ciphertext = SalsaBox::new(&PublicKey::from(key), &secret)
        .encrypt(&nonce, plaintext.as_slice())
        .map_err(|_| anyhow::anyhow!("challenge encryption failed"))?;
    Ok((
        json!({"type":"host-challenge","challengeId":challenge_id,"relayEphemeralPublicKeyB64":STANDARD.encode(public.as_bytes()),"nonceB64":STANDARD.encode(nonce),"ciphertextB64":STANDARD.encode(ciphertext),"expiresAt":expires}),
        t,
        proof_secret,
    ))
}
async fn control(s: App, mut socket: WebSocket, mut c: auth::Claims) -> anyhow::Result<()> {
    let hello = read_json(&mut socket).await?;
    anyhow::ensure!(
        hello["type"] == "host-hello"
            && hello["v"] == 1
            && hello["relayHostId"] == c.host
            && hello["hostPublicKeyB64"] == c.key,
        "invalid host hello"
    );
    let epoch = hello["assignmentEpoch"].as_u64().unwrap_or(0);
    anyhow::ensure!(
        s.store.lock().unwrap().data.epochs.get(&c.host).copied() == Some(epoch),
        "stale assignment"
    );
    let (message, transcript, proof_secret) = challenge(&s, &c, &hello)?;
    let challenge_id = message["challengeId"].clone();
    send(&mut socket, message).await?;
    let answer = read_json(&mut socket).await?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&proof_secret)?;
    mac.update(b"orca-relay-host-proof/v1\0ack\0");
    mac.update(&transcript);
    let proof = STANDARD.decode(answer["proofB64"].as_str().unwrap_or(""))?;
    anyhow::ensure!(
        answer["type"] == "host-challenge-ack" && answer["challengeId"] == challenge_id,
        "bad challenge reply"
    );
    mac.verify_slice(&proof)
        .map_err(|_| anyhow::anyhow!("host key proof failed"))?;
    let generation = now();
    let (tx, mut rx) = mpsc::channel(32);
    let cancel = Arc::new(Notify::new());
    {
        let mut hosts = s.hosts.lock().unwrap();
        anyhow::ensure!(hosts.contains_key(&c.host) || hosts.len() < 8, "host limit");
        if let Some(old) = hosts.insert(
            c.host.clone(),
            Host {
                tx,
                generation,
                cancel: cancel.clone(),
            },
        ) {
            old.cancel.notify_waiters();
        }
    }
    // Guard ensures exceptional disconnects retire the control and its splice tasks.
    let _guard = ControlGuard {
        s: s.clone(),
        host: c.host.clone(),
        generation,
        cancel: cancel.clone(),
    };
    send(&mut socket,json!({"type":"host-hello-ack","v":1,"generation":generation,"controlResumeSecret":random(),"leaseExpiresAt":now()+HOUR,"activeConnIds":[],"pendingConns":[]})).await?;
    println!("host control authenticated");
    let mut heartbeat = tokio::time::interval(Duration::from_secs(20));
    let mut last_seen = now();
    loop {
        tokio::select! {
            _=cancel.notified()=>break,
            _=heartbeat.tick()=>{
                if now()>c.expires||now()>last_seen+75_000||!auth::session_live(&s,&c){break}
                send(&mut socket,json!({"type":"ping","t":now()})).await?;
            }
            next=rx.recv()=>match next{Some(v)=>send(&mut socket,v).await?,None=>break},
            next=socket.recv()=>match next{
                Some(Ok(Message::Ping(v)))=>{last_seen=now();socket.send(Message::Pong(v)).await?;}
                Some(Ok(Message::Pong(_)))=>last_seen=now(),
                Some(Ok(Message::Text(v)))=>{
                    last_seen=now();let v:Value=serde_json::from_str(&v)?;
                    if v["type"]=="auth-refresh" {
                        if let Some(new)=v["relayJwt"].as_str().and_then(|t|auth::verify(&s,t)).filter(|n|n.host==c.host&&n.key==c.key&&n.profile==c.profile){c=new;}else{break}
                    }else if v["type"]!="pong" {
                        let reply=handle_control(&s,&c.host,generation,&v).unwrap_or_else(|code|json!({"type":"control-error","reqId":v["reqId"],"code":code}));
                        send(&mut socket,reply).await?;
                    }
                }
                _=>break
            }
        }
    }
    Ok(())
}
struct ControlGuard {
    s: App,
    host: String,
    generation: u64,
    cancel: Arc<Notify>,
}
impl Drop for ControlGuard {
    fn drop(&mut self) {
        let mut hosts = self.s.hosts.lock().unwrap();
        if hosts
            .get(&self.host)
            .is_some_and(|h| h.generation == self.generation)
        {
            hosts.remove(&self.host);
        }
        self.cancel.notify_waiters();
        println!("host control disconnected");
    }
}

fn handle_control(s: &App, host: &str, generation: u64, v: &Value) -> Result<Value, &'static str> {
    let req = v["reqId"]
        .as_str()
        .filter(|v| valid_id(v))
        .ok_or("invalid_request")?;
    let typ = v["type"].as_str().ok_or("invalid_request")?;
    let device = v["relayDeviceId"].as_str().unwrap_or("");
    if typ != "device-resume-confirm" && !valid_id(device) {
        return Err("invalid_device");
    }
    let key = device_key(host, device);
    match typ {
        "invite-create" => {
            let token = random();
            let expires = now() + 10 * 60_000;
            let mut invites = s.invites.lock().unwrap();
            invites.retain(|_, i| i.expires > now());
            if invites.len() >= 32 {
                return Err("invite_limit");
            }
            invites.insert(
                hash(&token),
                Invite {
                    host: host.into(),
                    device: device.into(),
                    expires,
                    attempts: 0,
                },
            );
            Ok(
                json!({"type":"invite-created","reqId":req,"inviteToken":token,"expiresAt":expires,"maxAttempts":16}),
            )
        }
        "device-credential-install" => {
            let new_hash = v["newResumeTokenHash"]
                .as_str()
                .filter(|v| valid_token(v))
                .ok_or("invalid_hash")?;
            let mode = v["authorization"]["mode"]
                .as_str()
                .ok_or("invalid_authorization")?;
            if mode == "relay-basis" {
                let links = s.links.lock().unwrap();
                let basis = v["authorization"]["basisConnId"]
                    .as_str()
                    .and_then(|id| links.get(id))
                    .ok_or("invalid_basis")?;
                if basis.host != host
                    || basis.device != device
                    || !basis.attached
                    || basis.generation != generation
                    || basis.expires < now()
                {
                    return Err("invalid_basis");
                }
            } else if mode != "authenticated-direct"
                || v["authorization"]["directAuthId"].as_str().is_none()
            {
                return Err("invalid_authorization");
            }
            let request_hash = hash(v.to_string());
            let install_key = device_key(host, req);
            let mut db = s.store.lock().unwrap();
            if let Some(saved) = db.data.installs.get(&install_key) {
                return if saved["request"] == request_hash {
                    Ok(saved["result"].clone())
                } else {
                    Err("request_conflict")
                };
            }
            let old = db.data.devices.get(&key).cloned();
            if let Some(old) = &old {
                if v["expectedCurrentHash"].as_str() != Some(old.current.as_str()) {
                    return Err("credential_conflict");
                }
            } else if v["expectedCurrentHash"].is_string() {
                return Err("credential_conflict");
            }
            let version = old.as_ref().map_or(1, |d| d.version + 1);
            let expires = now() + MONTH;
            let grace_expires = now() + 10 * 60_000;
            let d = Device {
                host: host.into(),
                id: device.into(),
                current: new_hash.into(),
                expires,
                version,
                grace: old.as_ref().map(|d| d.current.clone()),
                grace_expires,
            };
            let mut result = json!({"type":"device-credential-installed","v":1,"reqId":req,"authorizationMode":mode,"currentVersion":version,"resumeExpiresAt":expires});
            if old.is_some() {
                result["graceExpiresAt"] = json!(grace_expires)
            }
            db.update(|data|{data.devices.insert(key,d);data.installs.insert(install_key,json!({"device":device,"request":request_hash,"result":result,"createdAt":now()}));data.installs.retain(|_,v|v["createdAt"].as_u64().unwrap_or(0)+MONTH>now());}).map_err(|_|"persistence_failed")?;
            s.invites
                .lock()
                .unwrap()
                .retain(|_, v| v.host != host || v.device != device);
            Ok(result)
        }
        "device-credential-install-status" => {
            let db = s.store.lock().unwrap();
            let saved = db
                .data
                .installs
                .get(&device_key(host, req))
                .filter(|v| v["device"] == device);
            let mut result = json!({"type":"device-credential-install-status-result","v":1,"reqId":req,"state":"not-found"});
            if let Some(saved) = saved {
                let mut payload = saved["result"].clone();
                payload.as_object_mut().unwrap().remove("type");
                result["state"] = json!("committed");
                result["result"] = payload;
            }
            Ok(result)
        }
        "device-resume-confirm" => {
            let links = s.links.lock().unwrap();
            let link = v["basisConnId"]
                .as_str()
                .and_then(|id| links.get(id))
                .ok_or("invalid_basis")?;
            if link.host != host
                || link.kind != "resume"
                || link.generation != generation
                || !link.attached
            {
                return Err("invalid_basis");
            }
            let key = device_key(host, &link.device);
            let mut db = s.store.lock().unwrap();
            let mut d = db.data.devices.get(&key).cloned().ok_or("device_revoked")?;
            let accepted_as = if same(&d.current, &link.accepted_hash) {
                "current"
            } else if d.grace_expires > now()
                && d.grace
                    .as_deref()
                    .is_some_and(|h| same(h, &link.accepted_hash))
            {
                "grace"
            } else {
                return Err("credential_conflict");
            };
            if accepted_as == "current" {
                d.expires = now() + MONTH;
                db.update(|data| data.devices.insert(key, d.clone()))
                    .map_err(|_| "persistence_failed")?;
            }
            Ok(
                json!({"type":"device-resume-confirmed","v":1,"reqId":req,"currentVersion":d.version,"acceptedAs":accepted_as,"renewed":accepted_as=="current","resumeExpiresAt":d.expires}),
            )
        }
        "device-revoke" => {
            s.store
                .lock()
                .unwrap()
                .update(|d| {
                    d.devices.remove(&key);
                    d.installs.retain(|k, v| {
                        !k.starts_with(&format!("{host}:")) || v["device"] != device
                    });
                })
                .map_err(|_| "persistence_failed")?;
            s.invites
                .lock()
                .unwrap()
                .retain(|_, v| v.host != host || v.device != device);
            s.links
                .lock()
                .unwrap()
                .retain(|_, v| v.host != host || v.device != device);
            Ok(json!({"type":"device-revoked","reqId":req}))
        }
        _ => Err("unsupported_request"),
    }
}

pub async fn data_upgrade(
    State(s): State<App>,
    Path(id): Path<String>,
    ws: WebSocketUpgrade,
) -> Result<Response, (StatusCode, Json<Value>)> {
    if !valid_id(&id) {
        return Err(bad("invalid_connection"));
    }
    let permit = limited(&s)?;
    Ok(ws
        .max_message_size(8 * 1024 * 1024)
        .on_upgrade(move |mut socket| async move {
            let _permit = permit;
            if let Ok(v) = read_json(&mut socket).await {
                let sender = {
                    let mut links = s.links.lock().unwrap();
                    links
                        .get_mut(&id)
                        .filter(|l| {
                            !l.attached
                                && l.expires > now()
                                && v["type"] == "host-data-auth"
                                && v["v"] == 1
                                && v["generation"] == l.generation
                                && v["connTicket"].as_str().is_some_and(|t| same(t, &l.ticket))
                        })
                        .and_then(|l| {
                            l.attached = true;
                            l.socket.take()
                        })
                };
                if let Some(sender) = sender {
                    let _ = sender.send(socket);
                }
            }
        })
        .into_response())
}
pub async fn phone_upgrade(
    State(s): State<App>,
    Path(host): Path<String>,
    ws: WebSocketUpgrade,
) -> Result<Response, (StatusCode, Json<Value>)> {
    if host.len() != 16 || !valid_id(&host) {
        return Err(bad("invalid_host"));
    }
    let permit = limited(&s)?;
    Ok(ws
        .max_message_size(8 * 1024 * 1024)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            if let Err(e) = phone(s, socket, &host).await {
                eprintln!("phone connection ended: {e}")
            }
        })
        .into_response())
}
async fn reject(socket: &mut WebSocket, code: u16) -> anyhow::Result<()> {
    send(socket, json!({"type":"relay-hello","ok":false,"code":code})).await?;
    socket
        .send(Message::Close(Some(CloseFrame {
            code,
            reason: "relay unavailable".into(),
        })))
        .await?;
    Ok(())
}
async fn phone(s: App, mut socket: WebSocket, host: &str) -> anyhow::Result<()> {
    let v = read_json(&mut socket).await?;
    let token = v["credential"].as_str().unwrap_or("");
    if v["type"] != "relay-auth" || v["v"] != 1 || v["mode"] != "connect" || !valid_token(token) {
        return reject(&mut socket, 4401).await;
    }
    let token_hash = hash(token);
    let invite = {
        let mut invites = s.invites.lock().unwrap();
        invites
            .get_mut(&token_hash)
            .filter(|i| i.host == host && i.expires > now() && i.attempts < 16)
            .map(|i| {
                i.attempts += 1;
                i.device.clone()
            })
    };
    let (device, kind, version, accepted_as, resume_expires) = if let Some(device) = invite {
        (device, "invite", 0, "current".into(), 0)
    } else if let Some((d, a)) = lookup_device(&s, host, token) {
        (d.id, "resume", d.version, a, d.expires)
    } else {
        return reject(&mut socket, 4401).await;
    };
    let control = {
        s.hosts
            .lock()
            .unwrap()
            .get(host)
            .cloned()
            .filter(|h| !h.tx.is_closed())
    };
    let Some(control) = control else {
        return reject(&mut socket, 4404).await;
    };
    let conn = random();
    let ticket = random();
    let (tx, rx) = oneshot::channel();
    let admitted = {
        let mut links = s.links.lock().unwrap();
        if links.values().filter(|l| l.host == host).count() >= 8 {
            false
        } else {
            links.insert(
                conn.clone(),
                Link {
                    host: host.into(),
                    device: device.clone(),
                    ticket: ticket.clone(),
                    generation: control.generation,
                    kind: kind.into(),
                    expires: now() + 10_000,
                    accepted_hash: token_hash,
                    attached: false,
                    socket: Some(tx),
                },
            );
            true
        }
    };
    if !admitted {
        return reject(&mut socket, 4429).await;
    }
    let _guard = LinkGuard {
        s: s.clone(),
        id: conn.clone(),
    };
    control.tx.send(json!({"type":"conn-open","connId":conn,"connTicket":ticket,"kind":kind,"relayDeviceId":device,"attachDeadlineMs":10_000})).await?;
    let desktop = match tokio::time::timeout(Duration::from_secs(10), rx).await {
        Ok(Ok(socket)) => socket,
        _ => return reject(&mut socket, 4408).await,
    };
    if let Some(l) = s.links.lock().unwrap().get_mut(&conn) {
        l.expires = now() + MONTH;
    }
    let mut hello =
        json!({"type":"relay-hello","ok":true,"credentialKind":kind,"leaseExpiresAt":now()+HOUR});
    if kind == "resume" {
        hello["acceptedCredentialVersion"] = json!(version);
        hello["acceptedAs"] = json!(accepted_as);
        hello["resumeExpiresAt"] = json!(resume_expires);
        if accepted_as == "grace" {
            hello["graceExpiresAt"] = json!(now() + 10 * 60_000)
        }
    }
    send(&mut socket, hello).await?;
    println!("encrypted phone splice connected ({kind})");
    // No unbounded queues: each leg awaits writes and applies a slow-reader deadline.
    let (mut phone_tx, mut phone_rx) = socket.split();
    let (mut desktop_tx, mut desktop_rx) = desktop.split();
    let up = async {
        while let Some(Ok(message)) = phone_rx.next().await {
            if matches!(message, Message::Text(_) | Message::Binary(_)) {
                tokio::time::timeout(Duration::from_secs(30), desktop_tx.send(message)).await??;
            } else if matches!(message, Message::Close(_)) {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    let down = async {
        while let Some(Ok(message)) = desktop_rx.next().await {
            if matches!(message, Message::Text(_) | Message::Binary(_)) {
                tokio::time::timeout(Duration::from_secs(30), phone_tx.send(message)).await??;
            } else if matches!(message, Message::Close(_)) {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {r=up=>r?,r=down=>r?,_=control.cancel.notified()=>{},_=async{loop{tokio::time::sleep(Duration::from_secs(5)).await;if !s.links.lock().unwrap().contains_key(&conn){break}}}=>{}}
    Ok(())
}
struct LinkGuard {
    s: App,
    id: String,
}
impl Drop for LinkGuard {
    fn drop(&mut self) {
        self.s.links.lock().unwrap().remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_proof_encrypts_the_exact_bound_transcript() {
        let s = test_server();
        let host_secret = SecretKey::generate(&mut OsRng);
        let c = auth::Claims {
            session: "session".into(),
            host: "abcdefghijklmnop".into(),
            key: STANDARD.encode(host_secret.public_key().as_bytes()),
            user: "user".into(),
            profile: "profile".into(),
            expires: now() + HOUR,
        };
        let hello =
            json!({"assignmentEpoch":5,"previousGeneration":10,"controlResumeSecret":random()});
        let (challenge, t, secret) = challenge(&s, &c, &hello).unwrap();
        let peer: [u8; 32] = STANDARD
            .decode(challenge["relayEphemeralPublicKeyB64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let nonce = STANDARD
            .decode(challenge["nonceB64"].as_str().unwrap())
            .unwrap();
        let plaintext = SalsaBox::new(&PublicKey::from(peer), &host_secret)
            .decrypt(
                nonce.as_slice().into(),
                STANDARD
                    .decode(challenge["ciphertextB64"].as_str().unwrap())
                    .unwrap()
                    .as_slice(),
            )
            .unwrap();
        let domain = b"orca-relay-host-challenge/v1\0";
        assert_eq!(&plaintext[..domain.len()], domain);
        let length = u32::from_be_bytes(
            plaintext[domain.len()..domain.len() + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        assert_eq!(length, t.len());
        assert_eq!(&plaintext[domain.len() + 4..domain.len() + 4 + length], t);
        assert_eq!(&plaintext[domain.len() + 4 + length..], secret);
        let mut offset = 0;
        let mut fields = HashMap::new();
        while offset < t.len() {
            let n = u32::from_be_bytes(t[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            let name = String::from_utf8(t[offset..offset + n].to_vec()).unwrap();
            offset += n;
            let n = u32::from_be_bytes(t[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            fields.insert(name, t[offset..offset + n].to_vec());
            offset += n;
        }
        assert_eq!(fields.len(), 16);
        assert_eq!(fields["relayOrigin"], s.origin.as_bytes());
        assert_eq!(fields["userId"], b"user");
        assert_eq!(fields["previousGeneration"], 10u64.to_be_bytes());
        assert_eq!(fields["resumeRequested"], [1]);
    }
    #[test]
    fn credentials_rotate_idempotently_and_revoke() {
        let s = test_server();
        let host = "abcdefghijklmnop";
        let token = random();
        let install = json!({"type":"device-credential-install","v":1,"reqId":"install-1","relayDeviceId":"phone","newResumeTokenHash":hash(&token),"authorization":{"mode":"authenticated-direct","directAuthId":"direct-1"}});
        let first = handle_control(&s, host, 1, &install).unwrap();
        assert_eq!(first["currentVersion"], 1);
        assert_eq!(handle_control(&s, host, 1, &install).unwrap(), first);
        assert!(lookup_device(&s, host, &token).is_some());
        assert!(lookup_device(&s, "other-host", &token).is_none());
        let mut changed = install.clone();
        changed["newResumeTokenHash"] = json!(hash(random()));
        assert!(handle_control(&s, host, 1, &changed).is_err());
        changed["reqId"] = json!("install-2");
        assert!(handle_control(&s, host, 1, &changed).is_err());
        changed["expectedCurrentHash"] = json!(hash(&token));
        let second = handle_control(&s, host, 1, &changed).unwrap();
        assert_eq!(second["currentVersion"], 2);
        assert_eq!(lookup_device(&s, host, &token).unwrap().1, "grace");
        let mut bad = install.clone();
        bad["reqId"] = json!("install-bad");
        bad["authorization"] = json!({"mode":"relay-basis","basisConnId":"unknown"});
        assert!(handle_control(&s, host, 1, &bad).is_err());
        handle_control(
            &s,
            host,
            1,
            &json!({"type":"device-revoke","reqId":"revoke-1","relayDeviceId":"phone"}),
        )
        .unwrap();
        assert!(lookup_device(&s, host, &token).is_none());
    }
}
