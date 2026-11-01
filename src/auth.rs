use super::*;
use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, header},
    response::{Html, IntoResponse, Redirect, Response},
};
use hmac::{Hmac, Mac};

#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub profile: String,
    pub access_hash: String,
    pub access_expires: u64,
    pub refresh_expires: u64,
}
pub struct Code {
    query: LoginQuery,
    expires: u64,
}
#[derive(Clone, Deserialize, Serialize)]
pub struct LoginQuery {
    client_id: String,
    response_type: String,
    redirect_uri: String,
    nonce: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
    local_profile_id: String,
}
#[derive(Deserialize)]
pub struct LoginForm {
    password: String,
    request: String,
}
pub fn bearer(h: &HeaderMap) -> Option<&str> {
    h.get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}
pub fn current(s: &Server, h: &HeaderMap) -> Result<Session, (StatusCode, Json<Value>)> {
    let digest = hash(bearer(h).ok_or_else(denied)?);
    s.store
        .lock()
        .unwrap()
        .data
        .sessions
        .values()
        .find(|v| {
            same(&v.access_hash, &digest) && v.access_expires > now() && v.refresh_expires > now()
        })
        .cloned()
        .ok_or_else(denied)
}
fn validate(q: &LoginQuery) -> Result<(), (StatusCode, Json<Value>)> {
    let u = url::Url::parse(&q.redirect_uri).map_err(|_| bad("invalid_redirect"))?;
    if u.scheme() != "http"
        || u.host_str() != Some("127.0.0.1")
        || u.port().is_none()
        || u.path() != "/auth/callback"
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err(bad("invalid_redirect"));
    }
    if q.client_id != "orca-desktop"
        || q.response_type != "code"
        || q.code_challenge_method != "S256"
        || q.code_challenge.len() != 43
        || q.local_profile_id.is_empty()
        || q.local_profile_id.len() > 128
        || q.nonce.len() > 128
        || q.state.len() > 128
        || q.nonce.len() < 16
        || q.state.len() < 16
    {
        return Err(bad("invalid_authorization_request"));
    }
    Ok(())
}
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
pub async fn login_page(
    Query(q): Query<LoginQuery>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    validate(&q)?;
    Ok(login_response(&q, None, StatusCode::OK))
}
fn login_response(q: &LoginQuery, error: Option<&str>, status: StatusCode) -> Response {
    let request = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&q).unwrap());
    let error = error.map(|message| format!("<p role=alert>{}</p>", escape(message))).unwrap_or_default();
    let html = format!(
        "<!doctype html><html lang=ru><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Private Orca Relay</title><style>body{{font:18px system-ui;background:#11131a;color:#eee;max-width:440px;margin:14vh auto;padding:24px}}input,button{{box-sizing:border-box;width:100%;padding:14px;margin-top:18px;border-radius:10px;border:1px solid #667}}button{{background:#a6b8ff;color:#111;font-weight:700}}</style><h1>Подключить Orca</h1><p>Введите код, который показала программа установки. Он действует 10 минут и используется один раз.</p>{error}<form method=post><input type=hidden name=request value=\"{}\"><label>Код подключения<input type=password name=password required autocomplete=one-time-code></label><button>Подключить Orca</button></form></html>",
        escape(&request)
    );
    let mut r = (status, Html(html)).into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    r.headers_mut().insert(header::CONTENT_SECURITY_POLICY,"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'".parse().unwrap());
    r
}
pub async fn authorize(
    State(s): State<App>,
    Form(f): Form<LoginForm>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    setup::rate_limit(&s)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(f.request)
        .map_err(|_| bad("invalid_request"))?;
    let q: LoginQuery = serde_json::from_slice(&bytes).map_err(|_| bad("invalid_request"))?;
    validate(&q)?;
    let code = random();
    let mut u = url::Url::parse(&q.redirect_uri).unwrap();
    u.query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &q.state);
    let mut codes = s.auth_codes.lock().unwrap();
    codes.retain(|_, v| v.expires > now());
    if codes.len() >= 16 {
        return Err(fail(StatusCode::TOO_MANY_REQUESTS, "code_limit"));
    }
    if !same(&hash(&f.password), &s.owner_hash) {
        if let Err(error) = setup::consume(&s, &f.password) {
            if error.0 == StatusCode::UNAUTHORIZED {
                return Ok(login_response(&q, Some("Код неверен, истёк или уже использован. Получите новый код командой ./relay code на установочном компьютере."), StatusCode::UNAUTHORIZED));
            }
            return Err(error);
        }
    }
    codes.insert(
        hash(code),
        Code {
            query: q,
            expires: now() + 60_000,
        },
    );
    Ok(Redirect::to(u.as_str()).into_response())
}
fn summary(data: &Data, session: &Session, access: Option<&str>, refresh: Option<&str>) -> Value {
    let mut v = json!({"cloud":{"cloudProfileId":session.profile,"userId":data.user_id,"email":"owner@private-relay.invalid","displayName":"Private Relay","linkedAt":now()},"capabilities":{"flags":{"relay.use":true},"refreshedAt":now()},"organizations":[]});
    if let Some(t) = access {
        v["accessToken"] = json!(t);
        v["expiresAt"] = json!(session.access_expires)
    }
    if let Some(t) = refresh {
        v["refreshToken"] = json!(t)
    }
    v
}
pub async fn exchange(State(s): State<App>, Json(v): Json<Value>) -> ApiResult {
    let code = text(&v, "code")?;
    let verifier = text(&v, "codeVerifier")?;
    let c = s
        .auth_codes
        .lock()
        .unwrap()
        .remove(&hash(code))
        .ok_or_else(denied)?;
    if c.expires < now()
        || !same(&hash(verifier), &c.query.code_challenge)
        || text(&v, "nonce")? != c.query.nonce
        || text(&v, "state")? != c.query.state
        || text(&v, "redirectUri")? != c.query.redirect_uri
        || text(&v, "localProfileId")? != c.query.local_profile_id
    {
        return Err(denied());
    }
    let access = random();
    let refresh = random();
    let session = Session {
        id: random(),
        profile: c.query.local_profile_id,
        access_hash: hash(&access),
        access_expires: now() + HOUR,
        refresh_expires: now() + MONTH,
    };
    let mut db = s.store.lock().unwrap();
    db.update(|d| {
        d.sessions.retain(|_, s| s.refresh_expires > now());
        d.sessions.insert(hash(&refresh), session.clone());
    })
    .map_err(|_| db_error())?;
    Ok(Json(summary(
        &db.data,
        &session,
        Some(&access),
        Some(&refresh),
    )))
}
pub async fn refresh(State(s): State<App>, Json(v): Json<Value>) -> ApiResult {
    let refresh = text(&v, "refreshToken")?;
    let digest = hash(refresh);
    let mut db = s.store.lock().unwrap();
    let mut session = db
        .data
        .sessions
        .get(&digest)
        .filter(|v| v.refresh_expires > now())
        .cloned()
        .ok_or_else(denied)?;
    let access = random();
    session.access_hash = hash(&access);
    session.access_expires = now() + HOUR;
    db.update(|d| d.sessions.insert(digest, session.clone()))
        .map_err(|_| db_error())?;
    Ok(Json(summary(
        &db.data,
        &session,
        Some(&access),
        Some(refresh),
    )))
}
pub async fn capabilities(State(s): State<App>, h: HeaderMap) -> ApiResult {
    let session = current(&s, &h)?;
    let db = s.store.lock().unwrap();
    Ok(Json(summary(&db.data, &session, None, None)))
}
pub async fn logout(State(s): State<App>, h: HeaderMap, Json(v): Json<Value>) -> ApiResult {
    let session = current(&s, &h)?;
    let refresh = text(&v, "refreshToken")?;
    let mut db = s.store.lock().unwrap();
    let key = hash(refresh);
    if !db
        .data
        .sessions
        .get(&key)
        .is_some_and(|v| v.profile == session.profile)
    {
        return Err(denied());
    }
    db.update(|d| d.sessions.remove(&key))
        .map_err(|_| db_error())?;
    Ok(Json(json!({"ok":true})))
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Claims {
    pub session: String,
    pub host: String,
    pub key: String,
    pub user: String,
    pub profile: String,
    pub expires: u64,
}
pub fn sign(s: &Server, c: &Claims) -> String {
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(c).unwrap());
    let mut mac = Hmac::<Sha256>::new_from_slice(&s.signing_key).unwrap();
    mac.update(payload.as_bytes());
    format!(
        "{payload}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}
pub fn verify(s: &Server, token: &str) -> Option<Claims> {
    let (p, sig) = token.split_once('.')?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&s.signing_key).ok()?;
    mac.update(p.as_bytes());
    mac.verify_slice(&URL_SAFE_NO_PAD.decode(sig).ok()?).ok()?;
    let c: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).ok()?).ok()?;
    if c.expires <= now() {
        return None;
    }
    if !session_live(s, &c) {
        return None;
    }
    Some(c)
}
pub fn session_live(s: &Server, c: &Claims) -> bool {
    s.store
        .lock()
        .unwrap()
        .data
        .sessions
        .values()
        .any(|v| v.id == c.session && v.profile == c.profile && v.refresh_expires > now())
}
pub async fn relay_token(State(s): State<App>, h: HeaderMap, Json(v): Json<Value>) -> ApiResult {
    let session = current(&s, &h)?;
    let host = text(&v, "relayHostId")?;
    let key = text(&v, "hostPublicKeyB64")?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(key)
        .map_err(|_| bad("invalid_key"))?;
    if raw.len() != 32 || host != &hash(&raw)[..16] {
        return Err(bad("host_key_mismatch"));
    }
    let c = Claims {
        session: session.id,
        host: host.into(),
        key: key.into(),
        profile: session.profile,
        user: s.store.lock().unwrap().data.user_id.clone(),
        expires: now() + HOUR,
    };
    Ok(Json(
        json!({"relayToken":sign(&s,&c),"expiresAt":c.expires}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn relay_tokens_are_signed_expire_and_are_bound_to_login_session() {
        let s = test_server();
        let session = Session {
            id: "session1".into(),
            profile: "profile".into(),
            access_hash: hash("access"),
            access_expires: now() + HOUR,
            refresh_expires: now() + MONTH,
        };
        s.store
            .lock()
            .unwrap()
            .update(|d| {
                d.sessions.insert(hash("refresh"), session);
            })
            .unwrap();
        let mut c = Claims {
            session: "session1".into(),
            host: "host".into(),
            key: "key".into(),
            user: "user".into(),
            profile: "profile".into(),
            expires: now() + HOUR,
        };
        let token = sign(&s, &c);
        assert!(verify(&s, &token).is_some());
        assert!(verify(&s, &format!("{token}x")).is_none());
        c.expires = now() - 1;
        assert!(verify(&s, &sign(&s, &c)).is_none());
        s.store
            .lock()
            .unwrap()
            .update(|d| d.sessions.clear())
            .unwrap();
        assert!(verify(&s, &token).is_none());
    }
    #[test]
    fn redirect_is_loopback_only() {
        let mut q = LoginQuery {
            client_id: "orca-desktop".into(),
            response_type: "code".into(),
            redirect_uri: "http://127.0.0.1:43210/auth/callback".into(),
            nonce: random(),
            state: random(),
            code_challenge: random(),
            code_challenge_method: "S256".into(),
            local_profile_id: "test".into(),
        };
        assert!(validate(&q).is_ok());
        for url in [
            "https://evil.com/auth/callback",
            "http://127.0.0.1:9/other",
            "http://user@127.0.0.1:9/auth/callback",
            "http://127.0.0.1:9/auth/callback?x=1",
        ] {
            q.redirect_uri = url.into();
            assert!(validate(&q).is_err());
        }
    }
}
