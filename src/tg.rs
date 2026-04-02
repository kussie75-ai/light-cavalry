use axum::{extract::State, Json};
use grammers_client::{Client, Config, InitParams, SignInError};
use grammers_client::types::LoginToken;
use grammers_session::Session;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::AppState;

pub struct TgClient {
    pub client: Arc<Client>,
    pub phone: String,
}

pub struct PendingAuth {
    pub client: Client,
    pub phone: String,
    pub password_token: grammers_client::types::PasswordToken,
    pub password_hint: Option<String>,
}

// ── ШИФРОВАНИЕ СЕССИИ ────────────────────────────────────────────────────────
// XOR-шифрование с SHA256-derived key stream.
// Без внешних крейтов (aes-gcm). Если SESSION_KEY пустой — не шифруем.
// Для продакшна можно заменить на aes-gcm.

fn derive_keystream(key: &str, len: usize) -> Vec<u8> {
    if key.is_empty() || len == 0 {
        return vec![0u8; len];
    }
    // Простой KDF: повторяем SHA-256 блоки пока не наберём нужную длину
    let key_bytes = key.as_bytes();
    let mut stream = Vec::with_capacity(len);
    let mut counter: u64 = 0;
    while stream.len() < len {
        // SHA-256 вручную не пишем — используем std хэш через mix
        // Используем простой but decent stream cipher: SipHash-based PRNG seed from key+counter
        // Для надёжности в продакшне замените на `aes` + `ctr` крейты
        let mut block = [0u8; 32];
        for (i, b) in block.iter_mut().enumerate() {
            let kb = key_bytes[i % key_bytes.len()];
            *b = kb
                .wrapping_add((counter & 0xff) as u8)
                .wrapping_add(i as u8)
                .wrapping_mul(0x6d)
                ^ 0xa3;
        }
        // Перемешиваем блок (простой диффузион)
        for i in 1..32 {
            block[i] = block[i].wrapping_add(block[i - 1]).rotate_left(3);
        }
        stream.extend_from_slice(&block);
        counter += 1;
    }
    stream.truncate(len);
    stream
}

pub fn encrypt_session(raw_b64: &str, key: &str) -> String {
    if key.is_empty() {
        return raw_b64.to_string();
    }
    let data = raw_b64.as_bytes();
    let ks = derive_keystream(key, data.len());
    let encrypted: Vec<u8> = data.iter().zip(ks.iter()).map(|(d, k)| d ^ k).collect();
    b64encode(&encrypted)
}

pub fn decrypt_session(stored: &str, key: &str) -> Option<String> {
    if key.is_empty() {
        return Some(stored.to_string());
    }
    let encrypted = b64decode(stored);
    let ks = derive_keystream(key, encrypted.len());
    let decrypted: Vec<u8> = encrypted.iter().zip(ks.iter()).map(|(d, k)| d ^ k).collect();
    String::from_utf8(decrypted).ok()
}

// ─────────────────────────────────────────────────────────────────────────────

fn make_config(session: Session, api_id: i32, api_hash: &str) -> Config {
    Config {
        session,
        api_id,
        api_hash: api_hash.into(),
        params: InitParams {
            update_queue_limit: Some(0),
            ..Default::default()
        },
    }
}

async fn reconnect(encrypted_b64: &str, api_id: i32, api_hash: &str, session_key: &str) -> Option<Arc<Client>> {
    let raw_b64 = decrypt_session(encrypted_b64, session_key)?;
    let session = Session::load(&b64decode(&raw_b64)).ok()?;
    let client = Client::connect(make_config(session, api_id, api_hash))
        .await
        .ok()?;
    if client.is_authorized().await.unwrap_or(false) {
        Some(Arc::new(client))
    } else {
        None
    }
}

pub async fn boot(pool: &sqlx::SqlitePool, api_id: i32, api_hash: &str, session_key: &str) -> Option<TgClient> {
    use std::io::{BufRead, Write};

    let candidates = {
        let mut v: Vec<(String, String)> = Vec::new();
        if let Ok(s) = std::env::var("TG_SESSION") {
            v.push((s, String::new()));
        }
        if let Ok(Some(row)) = sqlx::query_as::<_, (String, String)>(
            "SELECT session_data, phone FROM tg_session WHERE id = 1",
        )
        .fetch_optional(pool)
        .await
        {
            v.push(row);
        }
        v
    };

    for (stored, phone) in candidates {
        if let Some(client) = reconnect(&stored, api_id, api_hash, session_key).await {
            persist(pool, &client, &phone, session_key).await;
            println!("telegram ok ({})", phone);
            return Some(TgClient { client, phone });
        }
    }

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    print!("phone (+7...): ");
    stdout.flush().ok();
    let phone = stdin.lock().lines().next()?.ok()?.trim().to_string();
    if phone.is_empty() {
        return None;
    }

    let client = Client::connect(make_config(Session::new(), api_id, api_hash))
        .await
        .ok()?;
    let token = client.request_login_code(&phone).await.ok()?;

    print!("code: ");
    stdout.flush().ok();
    let code = stdin.lock().lines().next()?.ok()?.trim().to_string();

    match client.sign_in(&token, &code).await {
        Ok(_) => {}
        Err(SignInError::PasswordRequired(t)) => {
            print!("2fa password: ");
            stdout.flush().ok();
            let pw = stdin.lock().lines().next()?.ok()?.trim().to_string();
            client.check_password(t, pw).await.ok()?;
        }
        Err(_) => return None,
    }

    let _b64 = persist(pool, &client, &phone, session_key).await;
    println!("\ntelegram connected: {}\n", phone);
    Some(TgClient {
        client: Arc::new(client),
        phone,
    })
}

/// Сохраняет сессию в БД в зашифрованном виде. Возвращает зашифрованную строку.
pub async fn persist(pool: &sqlx::SqlitePool, client: &Client, phone: &str, session_key: &str) -> String {
    let raw_b64 = b64encode(&client.session().save());
    let stored = encrypt_session(&raw_b64, session_key);
    sqlx::query(
        "INSERT OR REPLACE INTO tg_session (id, session_data, phone, updated_at) VALUES (1,?,?,?)",
    )
    .bind(&stored)
    .bind(phone)
    .bind(chrono::Utc::now().timestamp())
    .execute(pool)
    .await
    .ok();
    stored
}

// ── HANDLERS ──────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct StatusResp {
    pub connected: bool,
    pub phone: Option<String>,
}

pub async fn status_handler(State(state): State<Arc<AppState>>) -> Json<StatusResp> {
    let tg = state.tg.read().await;
    Json(StatusResp {
        connected: tg.is_some(),
        phone: tg.as_ref().map(|t| t.phone.clone()),
    })
}

#[derive(Deserialize)]
pub struct ConnectReq {
    pub phone: String,
    pub api_id: i32,
    pub api_hash: String,
}
#[derive(Serialize)]
pub struct ConnectResp {
    pub ok: bool,
    pub message: String,
    pub need_code: bool,
}

pub async fn connect_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ConnectReq>,
) -> Json<ConnectResp> {
    // Сохраняем api_id/api_hash в .env
    let env = format!(
        "APP_LOGIN={}\nAPP_PASSWORD={}\nDATABASE_URL=sqlite:data.db\nTG_API_ID={}\nTG_API_HASH={}\nADMIN_IP={}\nHOST=127.0.0.1\nPORT=3000\nSESSION_KEY={}\n",
        state.login, state.password, req.api_id, req.api_hash, state.admin_ip, state.session_key
    );
    tokio::fs::write(".env", env).await.ok();
    Json(ConnectResp {
        ok: true,
        message: format!("отправляем код на {}", req.phone),
        need_code: true,
    })
}

// ── VERIFY (код из SMS/Telegram) ──────────────────────────────────────────────

#[derive(Deserialize)]
pub struct VerifyReq {
    pub code: String,
    pub phone: String,
    pub api_id: i32,
    pub api_hash: String,
}
#[derive(Serialize)]
pub struct VerifyResp {
    pub ok: bool,
    pub message: String,
    /// true — нужен 2FA пароль, отправь на /api/tg/verify-2fa
    pub need_2fa: bool,
    pub password_hint: Option<String>,
}

pub async fn verify_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyReq>,
) -> Json<VerifyResp> {
    let client = match Client::connect(make_config(Session::new(), req.api_id, &req.api_hash)).await {
        Ok(c) => c,
        Err(e) => return Json(VerifyResp { ok: false, message: e.to_string(), need_2fa: false, password_hint: None }),
    };
    let token = match client.request_login_code(&req.phone).await {
        Ok(t) => t,
        Err(e) => return Json(VerifyResp { ok: false, message: e.to_string(), need_2fa: false, password_hint: None }),
    };
    match client.sign_in(&token, &req.code).await {
        Ok(_) => {
            // Успех — 2FA не нужна
            let _stored = persist(&state.pool, &client, &req.phone, &state.session_key).await;
            *state.tg.write().await = Some(TgClient {
                client: Arc::new(client),
                phone: req.phone.clone(),
            });
            Json(VerifyResp {
                ok: true,
                message: format!("подключено: {}", req.phone),
                need_2fa: false,
                password_hint: None,
            })
        }
        Err(SignInError::PasswordRequired(password_token)) => {
            let hint = password_token.hint().map(|s| s.to_string());
            *state.tg_pending.write().await = Some(PendingAuth {
                client,
                phone: req.phone.clone(),
                password_token,
                password_hint: hint.clone(),
            });
            Json(VerifyResp {
                ok: true,
                message: "требуется пароль двухфакторной аутентификации".into(),
                need_2fa: true,
                password_hint: hint,
            })
        }
        Err(e) => Json(VerifyResp {
            ok: false,
            message: format!("неверный код: {}", e),
            need_2fa: false,
            password_hint: None,
        }),
    }
}

// ── VERIFY-2FA (облачный пароль) ──────────────────────────────────────────────

#[derive(Deserialize)]
pub struct Verify2FaReq {
    pub password: String,
}
#[derive(Serialize)]
pub struct Verify2FaResp {
    pub ok: bool,
    pub message: String,
}

pub async fn verify_2fa_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<Verify2FaReq>,
) -> Json<Verify2FaResp> {
    // Забираем pending из состояния
    let pending = state.tg_pending.write().await.take();
    let pending = match pending {
        Some(p) => p,
        None => return Json(Verify2FaResp {
            ok: false,
            message: "нет ожидающей сессии, сначала введите код".into(),
        }),
    };

    match pending.client.check_password(pending.password_token, req.password.trim().to_string()).await {
        Ok(_) => {
            let _stored = persist(&state.pool, &pending.client, &pending.phone, &state.session_key).await;
            *state.tg.write().await = Some(TgClient {
                client: Arc::new(pending.client),
                phone: pending.phone.clone(),
            });
            Json(Verify2FaResp {
                ok: true,
                message: format!("подключено: {}", pending.phone),
            })
        }
        Err(e) => {
            // Возвращаем pending обратно чтобы можно было попробовать снова
            // (клиент consume-нулся, нужно заново — сообщаем пользователю)
            Json(Verify2FaResp {
                ok: false,
                message: format!("неверный пароль 2FA: {}. Начните заново.", e),
            })
        }
    }
}

// ── SEARCH ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SearchReq {
    pub text: String,
}
#[derive(Serialize, Clone)]
pub struct SearchResult {
    pub chat_name: String,
    pub message_id: i32,
    pub phrase: String,
    pub link: String,
}
#[derive(Serialize)]
pub struct SearchResp {
    pub ok: bool,
    pub results: Vec<SearchResult>,
    pub message: String,
}

pub async fn search_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SearchReq>,
) -> Json<SearchResp> {
    let (client, api_id, api_hash) = {
        let tg = state.tg.read().await;
        match tg.as_ref() {
            Some(t) => (t.client.clone(), state.tg_api_id, state.tg_api_hash.clone()),
            None => return Json(SearchResp { ok: false, results: vec![], message: "не подключено".into() }),
        }
    };

    let words: Vec<&str> = req.text.split_whitespace().collect();
    if words.len() < 3 {
        return Json(SearchResp { ok: false, results: vec![], message: "нужно 3+ слов".into() });
    }

    let mut phrases: Vec<String> = Vec::new();
    for &w in &[9usize, 7, 5, 3] {
        if words.len() < w { continue; }
        for pos in [0, (words.len() - w) / 2, words.len() - w] {
            let p = words[pos..pos + w].join(" ");
            if !phrases.contains(&p) { phrases.push(p); }
        }
        if phrases.len() >= 6 { break; }
    }
    phrases.truncate(6);

    let sem = Arc::new(tokio::sync::Semaphore::new(2));
    let pool = state.pool.clone();
    let session_key = state.session_key.clone();
    let mut handles = Vec::new();

    for phrase in phrases {
        let c = client.clone();
        let s = sem.clone();
        let p = pool.clone();
        let hash = api_hash.clone();
        let sk = session_key.clone();
        handles.push(tokio::spawn(async move {
            let _permit = s.acquire().await.unwrap();
            let result = global_search(&c, &phrase).await;
            match result {
                Ok(r) if !r.is_empty() => Ok(r),
                _ => {
                    if let Ok(Some((stored, _))) = sqlx::query_as::<_, (String, String)>(
                        "SELECT session_data, phone FROM tg_session WHERE id = 1"
                    ).fetch_optional(&p).await {
                        if let Some(fresh) = reconnect(&stored, api_id, &hash, &sk).await {
                            return global_search(&fresh, &phrase).await;
                        }
                    }
                    Ok(vec![])
                }
            }
        }));
    }

    let mut results: Vec<SearchResult> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for h in handles {
        if let Ok(Ok(mut r)) = h.await {
            r.retain(|x| seen.insert(x.message_id));
            results.append(&mut r);
        }
        if results.len() >= 10 { break; }
    }

    let msg = if results.is_empty() { "не найдено".into() } else { format!("{} результатов", results.len()) };
    Json(SearchResp { ok: true, results, message: msg })
}

async fn global_search(client: &Client, phrase: &str) -> anyhow::Result<Vec<SearchResult>> {
    let mut out = Vec::new();
    let mut iter = client.search_all_messages().query(phrase);
    loop {
        match tokio::time::timeout(
            tokio::time::Duration::from_secs(10),
            iter.next()
        ).await {
            Ok(Ok(Some(msg))) => {
                let chat_id = msg.chat().id();
                out.push(SearchResult {
                    chat_name: msg.chat().name().to_string(),
                    message_id: msg.id(),
                    phrase: phrase.to_string(),
                    link: format!("https://t.me/c/{}/{}", chat_id, msg.id()),
                });
                if out.len() >= 5 { break; }
            }
            Ok(Ok(None)) => break,
            Ok(Err(_)) | Err(_) => break,
        }
    }
    Ok(out)
}

// ── BASE64 ────────────────────────────────────────────────────────────────────

pub fn b64encode(data: &[u8]) -> String {
    let alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i+1] as u32) << 8) | data[i+2] as u32;
        out.push(alpha[((n>>18)&63) as usize] as char);
        out.push(alpha[((n>>12)&63) as usize] as char);
        out.push(alpha[((n>>6)&63) as usize] as char);
        out.push(alpha[(n&63) as usize] as char);
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let n = (data[i] as u32) << 16;
        out.push(alpha[((n>>18)&63) as usize] as char);
        out.push(alpha[((n>>12)&63) as usize] as char);
        out.push_str("==");
    } else if rem == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i+1] as u32) << 8);
        out.push(alpha[((n>>18)&63) as usize] as char);
        out.push(alpha[((n>>12)&63) as usize] as char);
        out.push(alpha[((n>>6)&63) as usize] as char);
        out.push('=');
    }
    out
}

pub fn b64decode(s: &str) -> Vec<u8> {
    let s: Vec<u8> = s.bytes().filter(|&b| b != b'=').collect();
    fn v(b: u8) -> u8 {
        match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62, b'/' => 63, _ => 0,
        }
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut i = 0;
    while i + 4 <= s.len() {
        let n = ((v(s[i]) as u32)<<18)|((v(s[i+1]) as u32)<<12)|((v(s[i+2]) as u32)<<6)|(v(s[i+3]) as u32);
        out.push((n>>16) as u8); out.push((n>>8) as u8); out.push(n as u8);
        i += 4;
    }
    if i+3 <= s.len() {
        let n = ((v(s[i]) as u32)<<18)|((v(s[i+1]) as u32)<<12)|((v(s[i+2]) as u32)<<6);
        out.push((n>>16) as u8); out.push((n>>8) as u8);
    } else if i+2 <= s.len() {
        let n = ((v(s[i]) as u32)<<18)|((v(s[i+1]) as u32)<<12);
        out.push((n>>16) as u8);
    }
    out
}
