use axum::{
    extract::{ConnectInfo, Json, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;

mod analysis;
mod db;
mod tg;

pub struct AppState {
    pub pool: SqlitePool,
    pub tg: RwLock<Option<tg::TgClient>>,
    /// Временный клиент + phone пока ждём 2FA пароль
    pub tg_pending: RwLock<Option<tg::PendingAuth>>,
    pub login: String,
    pub password: String,
    pub tg_api_id: i32,
    pub tg_api_hash: String,
    pub admin_ip: String,
    /// Ключ для шифрования сессии в БД. Берётся из SESSION_KEY env.
    pub session_key: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    let database_url = std::env::var("DATABASE_URL").unwrap_or("sqlite:data.db".into());
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(
            database_url
                .parse::<sqlx::sqlite::SqliteConnectOptions>()?
                .create_if_missing(true),
        )
        .await?;

    db::init(&pool).await?;

    let login = std::env::var("APP_LOGIN").unwrap_or("admin".into());
    let password = std::env::var("APP_PASSWORD").unwrap_or("password".into());
    let tg_api_id: i32 = std::env::var("TG_API_ID")
        .unwrap_or_default()
        .parse()
        .unwrap_or(0);
    let tg_api_hash = std::env::var("TG_API_HASH").unwrap_or_default();
    let admin_ip = std::env::var("ADMIN_IP").unwrap_or_default();
    let session_key = std::env::var("SESSION_KEY").unwrap_or_else(|_| {
        eprintln!("WARNING: SESSION_KEY not set, session encryption disabled!");
        String::new()
    });

    let tg_client = if tg_api_id != 0 && !tg_api_hash.is_empty() {
        tg::boot(&pool, tg_api_id, &tg_api_hash, &session_key).await
    } else {
        println!("TG_API_ID / TG_API_HASH not set");
        None
    };

    let state = Arc::new(AppState {
        pool,
        tg: RwLock::new(tg_client),
        tg_pending: RwLock::new(None),
        login,
        password,
        tg_api_id,
        tg_api_hash,
        admin_ip,
        session_key,
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/api/auth", post(auth))
        .route("/api/check-session", post(check_session))
        .route("/api/analyze/repeats", post(analysis::repeats_handler))
        .route("/api/analyze/symbols", post(analysis::symbols_handler))
        .route("/api/analyze/compare", post(analysis::compare_handler))
        .route("/api/tg/connect", post(tg::connect_handler))
        .route("/api/tg/verify", post(tg::verify_handler))
        .route("/api/tg/verify-2fa", post(tg::verify_2fa_handler))
        .route("/api/tg/search", post(tg::search_handler))
        .route("/api/tg/status", get(tg::status_handler))
        .route("/api/admin/check", get(admin_check))
        .route("/api/admin/change-creds", post(change_creds))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let host = std::env::var("HOST").unwrap_or("127.0.0.1".into());
    let port: u16 = std::env::var("PORT")
        .unwrap_or("3000".into())
        .parse()
        .unwrap_or(3000);
    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;

    println!("http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

#[derive(Deserialize)]
struct AuthReq {
    login: String,
    password: String,
}
#[derive(Serialize)]
struct AuthResp {
    ok: bool,
    message: String,
}

async fn auth(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuthReq>,
) -> Response {
    if req.login != state.login || req.password != state.password {
        return (
            StatusCode::UNAUTHORIZED,
            Json(AuthResp {
                ok: false,
                message: "неверные данные".into(),
            }),
        )
            .into_response();
    }
    let ip = addr.ip().to_string();
    let expires = chrono::Utc::now().timestamp() + 86400 * 30;
    sqlx::query("INSERT OR REPLACE INTO sessions (ip, expires_at) VALUES (?, ?)")
        .bind(&ip)
        .bind(expires)
        .execute(&state.pool)
        .await
        .ok();
    Json(AuthResp {
        ok: true,
        message: "ok".into(),
    })
    .into_response()
}

#[derive(Serialize)]
struct SessionResp {
    valid: bool,
}

async fn check_session(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
) -> Json<SessionResp> {
    let ip = addr.ip().to_string();
    let now = chrono::Utc::now().timestamp();
    let row = sqlx::query_as::<_, (i64,)>("SELECT expires_at FROM sessions WHERE ip = ?")
        .bind(&ip)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);
    Json(SessionResp {
        valid: row.map(|(e,)| e > now).unwrap_or(false),
    })
}

#[derive(Deserialize)]
struct ChangeCredsReq {
    old_password: String,
    new_login: String,
    new_password: String,
}

async fn admin_check(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
) -> Response {
    let is_admin = state.admin_ip.is_empty() || addr.ip().to_string() == state.admin_ip;
    Json(serde_json::json!({ "is_admin": is_admin })).into_response()
}

async fn change_creds(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<ChangeCredsReq>,
) -> Response {
    if !state.admin_ip.is_empty() && addr.ip().to_string() != state.admin_ip {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"ok":false,"message":"forbidden"})),
        )
            .into_response();
    }
    if req.old_password != state.password {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"ok":false,"message":"wrong password"})),
        )
            .into_response();
    }
    let env = format!(
        "APP_LOGIN={}\nAPP_PASSWORD={}\nDATABASE_URL=sqlite:data.db\nTG_API_ID={}\nTG_API_HASH={}\nADMIN_IP={}\nHOST=127.0.0.1\nPORT=3000\nSESSION_KEY={}\n",
        req.new_login, req.new_password, state.tg_api_id, state.tg_api_hash, state.admin_ip, state.session_key
    );
    match tokio::fs::write(".env", env).await {
        Ok(_) => Json(serde_json::json!({"ok":true,"message":"restart required"})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"ok":false,"message":e.to_string()})),
        )
            .into_response(),
    }
}
