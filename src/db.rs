use sqlx::SqlitePool;

pub async fn init(pool: &SqlitePool) -> anyhow::Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sessions (
            ip TEXT PRIMARY KEY,
            expires_at INTEGER NOT NULL
        )"
    ).execute(pool).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tg_session (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            session_data TEXT NOT NULL,
            phone TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        )"
    ).execute(pool).await?;

    Ok(())
}
