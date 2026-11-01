//! Short-lived setup codes authorize one normal stock-client PKCE login.
use super::*;
use axum::{extract::State, http::HeaderMap};

const LIFETIME: u64 = 10 * 60_000;
const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Clone, Serialize, Deserialize)]
pub struct SetupCode {
    expires: u64,
}

pub fn digest(code: &str) -> Option<String> {
    let compact: String = code.chars().filter(|c| *c != '-').collect();
    let compact = compact.to_ascii_uppercase();
    if compact.len() != 12 || !compact.bytes().all(|c| ALPHABET.contains(&c)) {
        return None;
    }
    Some(hash(format!("orca-setup/v1:{compact}")))
}

pub fn rate_limit(s: &Server) -> Result<(), (StatusCode, Json<Value>)> {
    let mut attempts = s.login_attempts.lock().unwrap();
    attempts.retain(|t| *t + 60_000 > now());
    if attempts.len() >= 12 {
        return Err(fail(StatusCode::TOO_MANY_REQUESTS, "login_rate_limit"));
    }
    attempts.push(now());
    Ok(())
}

fn issue_code(s: &Server) -> ApiResult {
    let mut bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut bytes);
    let compact: String = bytes
        .iter()
        .map(|b| ALPHABET[(b & 31) as usize] as char)
        .collect();
    let code = format!("{}-{}-{}", &compact[..4], &compact[4..8], &compact[8..]);
    let expires = now() + LIFETIME;
    let mut db = s.store.lock().unwrap();
    if db
        .data
        .setup_codes
        .values()
        .filter(|v| v.expires > now())
        .count()
        >= 16
    {
        return Err(fail(StatusCode::TOO_MANY_REQUESTS, "setup_code_limit"));
    }
    db.update(|data| {
        data.setup_codes.retain(|_, v| v.expires > now());
        data.setup_codes
            .insert(digest(&code).unwrap(), SetupCode { expires });
    })
    .map_err(|_| db_error())?;
    Ok(Json(
        json!({"code":code,"expiresAt":expires,"expiresInSeconds":LIFETIME / 1000,"origin":s.origin}),
    ))
}

pub async fn issue(State(s): State<App>, h: HeaderMap) -> ApiResult {
    let token = auth::bearer(&h).ok_or_else(denied)?;
    if !same(&hash(token), &s.owner_hash) {
        return Err(denied());
    }
    issue_code(&s)
}

pub async fn check(State(s): State<App>, Json(v): Json<Value>) -> ApiResult {
    rate_limit(&s)?;
    let key = digest(text(&v, "code")?).ok_or_else(denied)?;
    let db = s.store.lock().unwrap();
    let code = db
        .data
        .setup_codes
        .get(&key)
        .filter(|v| v.expires > now())
        .ok_or_else(denied)?;
    Ok(Json(
        json!({"ok":true,"expiresAt":code.expires,"origin":s.origin}),
    ))
}

// Caller validates the PKCE request and reserves capacity before consuming a code.
pub fn consume(s: &Server, candidate: &str) -> Result<(), (StatusCode, Json<Value>)> {
    let key = digest(candidate).ok_or_else(denied)?;
    let mut db = s.store.lock().unwrap();
    if !db
        .data
        .setup_codes
        .get(&key)
        .is_some_and(|v| v.expires > now())
    {
        return Err(denied());
    }
    db.update(|data| data.setup_codes.remove(&key))
        .map_err(|_| db_error())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_is_hashed_normalized_and_can_be_used_only_once() {
        let s = test_server();
        let Json(result) = issue_code(&s).unwrap();
        let code = result["code"].as_str().unwrap();
        assert_eq!(code.len(), 14);
        let stored = serde_json::to_string(&s.store.lock().unwrap().data).unwrap();
        assert!(!stored.contains(code));
        assert_eq!(digest(code), digest(&code.replace('-', "").to_lowercase()));
        consume(&s, code).unwrap();
        assert!(consume(&s, code).is_err());
        assert!(digest("AAAA-AAAA-AAAA\n").is_none());
    }

    #[test]
    fn expired_codes_fail_and_old_databases_load_without_migration() {
        let s = test_server();
        let Json(result) = issue_code(&s).unwrap();
        let code = result["code"].as_str().unwrap();
        s.store
            .lock()
            .unwrap()
            .update(|data| {
                data.setup_codes
                    .values_mut()
                    .for_each(|v| v.expires = now() - 1)
            })
            .unwrap();
        assert!(consume(&s, code).is_err());
        let mut old = serde_json::to_value(&s.store.lock().unwrap().data).unwrap();
        old.as_object_mut().unwrap().remove("setup_codes");
        assert!(
            serde_json::from_value::<Data>(old)
                .unwrap()
                .setup_codes
                .is_empty()
        );
    }
}
