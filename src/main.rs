mod auth;
mod relay;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

pub type App = Arc<Server>;
pub type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;
pub const HOUR: u64 = 3_600_000;
pub const MONTH: u64 = 30 * 24 * HOUR;
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
pub fn random() -> String {
    let mut b = [0; 32];
    rand::thread_rng().fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}
pub fn hash(s: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(s.as_ref()))
}
pub fn same(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.as_bytes().ct_eq(b.as_bytes()).into()
}
pub fn fail(status: StatusCode, code: &str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({"error":code})))
}
pub fn bad(code: &str) -> (StatusCode, Json<Value>) {
    fail(StatusCode::BAD_REQUEST, code)
}
pub fn denied() -> (StatusCode, Json<Value>) {
    fail(StatusCode::UNAUTHORIZED, "unauthorized")
}
pub fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, (StatusCode, Json<Value>)> {
    v.get(k)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 8192)
        .ok_or_else(|| bad("invalid_field"))
}

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct Data {
    user_id: String,
    sessions: HashMap<String, auth::Session>,
    devices: HashMap<String, relay::Device>,
    installs: HashMap<String, Value>,
    epochs: HashMap<String, u64>,
}
pub struct Store {
    db: Connection,
    data: Data,
}
impl Store {
    fn open(path: &str) -> anyhow::Result<Self> {
        let db = Connection::open(path)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL);")?;
        let data =
            match db
                .query_row::<String, _, _>("SELECT data FROM state WHERE id=1", [], |r| r.get(0))
            {
                Ok(s) => serde_json::from_str(&s)?,
                Err(rusqlite::Error::QueryReturnedNoRows) => Data {
                    user_id: random(),
                    ..Default::default()
                },
                Err(e) => return Err(e.into()),
            };
        Ok(Self { db, data })
    }
    pub fn update<T>(&mut self, f: impl FnOnce(&mut Data) -> T) -> anyhow::Result<T> {
        let mut next = self.data.clone();
        let result = f(&mut next);
        self.db.execute("INSERT INTO state(id,data) VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET data=excluded.data",[serde_json::to_string(&next)?])?;
        self.data = next;
        Ok(result)
    }
}
pub struct Server {
    origin: String,
    owner_hash: String,
    signing_key: Vec<u8>,
    store: Mutex<Store>,
    auth_codes: Mutex<HashMap<String, auth::Code>>,
    hosts: Mutex<HashMap<String, relay::Host>>,
    invites: Mutex<HashMap<String, relay::Invite>>,
    links: Mutex<HashMap<String, relay::Link>>,
    login_attempts: Mutex<Vec<u64>>,
    sockets: Arc<tokio::sync::Semaphore>,
}
fn db_error() -> (StatusCode, Json<Value>) {
    fail(StatusCode::INTERNAL_SERVER_ERROR, "persistence_failed")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let origin = std::env::var("RELAY_ORIGIN")?;
    let parsed = url::Url::parse(&origin)?;
    anyhow::ensure!(
        parsed.scheme() == "https" && parsed.origin().ascii_serialization() == origin,
        "RELAY_ORIGIN must be an HTTPS origin without a trailing slash"
    );
    let owner = std::env::var("RELAY_OWNER_SECRET")?;
    anyhow::ensure!(
        owner.len() >= 32,
        "owner secret must have at least 32 characters"
    );
    let signing_key = std::env::var("RELAY_SIGNING_KEY")?.into_bytes();
    anyhow::ensure!(
        signing_key.len() >= 32,
        "signing key must have at least 32 characters"
    );
    let state = Arc::new(Server {
        origin,
        owner_hash: hash(owner),
        signing_key,
        store: Mutex::new(Store::open(
            &std::env::var("RELAY_DATABASE").unwrap_or("relay.sqlite".into()),
        )?),
        auth_codes: Default::default(),
        hosts: Default::default(),
        invites: Default::default(),
        links: Default::default(),
        login_attempts: Default::default(),
        sockets: Arc::new(tokio::sync::Semaphore::new(48)),
    });
    let router = router(state);
    let bind = std::env::var("RELAY_LISTEN").unwrap_or("127.0.0.1:6770".into());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!(
        "orca-private-relay {} listening on {}",
        env!("CARGO_PKG_VERSION"),
        bind
    );
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

fn router(state: App) -> Router {
    Router::new()
        .route("/healthz",get(||async {Json(json!({"ok":true,"service":"orca-private-relay","protocol":"orca-1.4.245","version":env!("CARGO_PKG_VERSION")}))}))
        .route("/v1/desktop/auth/authorize",get(auth::login_page).post(auth::authorize))
        .route("/v1/desktop/auth/session",post(auth::exchange))
        .route("/v1/desktop/auth/refresh",post(auth::refresh))
        .route("/v1/desktop/auth/capabilities",post(auth::capabilities))
        .route("/v1/desktop/auth/logout",post(auth::logout))
        .route("/v1/desktop/auth/relay-token",post(auth::relay_token))
        .route("/v1/regions",get(||async {Json(json!({"v":1,"regions":[]}))}))
        .route("/v1/assign",post(relay::assign))
        .route("/v1/resolve",post(relay::resolve))
        .route("/v1/host/control",get(relay::control_upgrade))
        .route("/v1/host/data/{id}",get(relay::data_upgrade))
        .route("/v1/connect/{host}",get(relay::phone_upgrade))
        .route("/admin/status",get(status))
        .layer(DefaultBodyLimit::max(32*1024))
        .with_state(state)
}
async fn status(State(s): State<App>, h: axum::http::HeaderMap) -> ApiResult {
    let token = auth::bearer(&h).ok_or_else(denied)?;
    if !same(&hash(token), &s.owner_hash) {
        return Err(denied());
    }
    let hosts = s
        .hosts
        .lock()
        .unwrap()
        .values()
        .filter(|h| !h.tx.is_closed())
        .count();
    let links = s.links.lock().unwrap().len();
    let db = s.store.lock().unwrap();
    Ok(Json(
        json!({"hosts":hosts,"connections":links,"devices":db.data.devices.len(),"sessions":db.data.sessions.len()}),
    ))
}

#[cfg(test)]
fn test_server() -> App {
    Arc::new(Server {
        origin: "https://relay.example.test".into(),
        owner_hash: hash("owner"),
        signing_key: vec![7; 32],
        store: Mutex::new(Store::open(":memory:").unwrap()),
        auth_codes: Default::default(),
        hosts: Default::default(),
        invites: Default::default(),
        links: Default::default(),
        login_attempts: Default::default(),
        sockets: Arc::new(tokio::sync::Semaphore::new(48)),
    })
}

#[cfg(test)]
mod wire_test;
