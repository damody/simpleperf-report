use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use rusqlite::{params_from_iter, types::Value, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;

pub const DEFAULT_PAGE_SIZE: u32 = 1000;
pub const MAX_PAGE_SIZE: u32 = 10000;

#[derive(Debug, Default, Clone, Deserialize)]
pub struct SourceQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub filter: Option<String>,
    pub cpu: Option<String>,
    pub thread: Option<String>,
    pub nonzero_only: Option<bool>,
    pub function_only: Option<bool>,
    pub sampled_first: Option<bool>,
    pub missing_only: Option<bool>,
    pub unresolved_only: Option<bool>,
    pub sort: Option<String>,
    pub desc: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceRowsResponse {
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
    pub rows: Vec<SourceLineDto>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceLineDto {
    pub file: String,
    pub line: u32,
    pub function: String,
    pub module: String,
    pub cpu: String,
    pub thread: String,
    pub status: String,
    pub code: String,
    pub detail: String,
    pub self_weight: f64,
    pub accumulated_weight: f64,
    pub p_pct: f64,
    pub acc_p_pct: f64,
    pub cpi: String,
    pub l1d_cache_hit_rate: String,
    pub mips: String,
    pub mcps: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileDto {
    pub file: String,
    pub self_weight: f64,
    pub accumulated_weight: f64,
    pub sample_count: u64,
    pub hot_lines: u64,
    pub missing: u64,
    pub unresolved: u64,
    pub hot_line: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionDto {
    pub function: String,
    pub file: String,
    pub line_start: u32,
    pub line_end: u32,
    pub module: String,
    pub self_weight: f64,
    pub accumulated_weight: f64,
    pub sample_count: u64,
    pub hot_lines: String,
}

#[derive(Clone)]
struct AppState {
    db_path: PathBuf,
}

pub fn clamp_limit(limit: Option<u32>) -> u32 {
    limit.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE)
}

pub async fn run_httpd(db_path: PathBuf, listen_ip: &str, port: u16) -> Result<()> {
    let state = AppState { db_path };
    let app = Router::new()
        .route("/", get(handle_report_html))
        .route("/api/summary", get(handle_summary))
        .route("/api/source-lines", get(handle_source_lines))
        .route("/api/files", get(handle_files))
        .route("/api/functions", get(handle_functions))
        .layer(CorsLayer::permissive())
        .with_state(state);
    let ip = if listen_ip.is_empty() {
        "127.0.0.1"
    } else {
        listen_ip
    };
    let addr: SocketAddr = format!("{ip}:{port}")
        .parse()
        .with_context(|| format!("Invalid listen address {ip}:{port}"))?;
    eprintln!("[HTTP] SourceLine report server listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

pub fn query_source_lines(db_path: &Path, query: &SourceQuery) -> Result<SourceRowsResponse> {
    let conn = open_readonly(db_path)?;
    let limit = clamp_limit(query.limit);
    let offset = query.offset.unwrap_or(0);
    let (where_sql, params) = source_where_clause(query);
    let order_by = source_order_by(
        query.sort.as_deref(),
        query.desc.unwrap_or(false),
        query.sampled_first.unwrap_or(false),
    );
    let total: u64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM source_lines{where_sql}"),
        params_from_iter(params.iter()),
        |row| row.get::<_, i64>(0).map(|value| value.max(0) as u64),
    )?;

    let mut select_params = params;
    select_params.push(Value::Integer(limit as i64));
    select_params.push(Value::Integer(offset as i64));
    let mut stmt = conn.prepare(&format!(
        "SELECT file, line, function, module, cpu, thread, status, code, detail,
                self_weight, accumulated_weight, p_pct, acc_p_pct,
                cpi, l1d_cache_hit_rate, mips, mcps
         FROM source_lines{where_sql} {order_by} LIMIT ? OFFSET ?"
    ))?;
    let rows = stmt
        .query_map(params_from_iter(select_params.iter()), |row| {
            Ok(SourceLineDto {
                file: row.get(0)?,
                line: row.get::<_, i64>(1)?.max(0) as u32,
                function: row.get(2)?,
                module: row.get(3)?,
                cpu: row.get(4)?,
                thread: row.get(5)?,
                status: row.get(6)?,
                code: row.get(7)?,
                detail: row.get(8)?,
                self_weight: row.get(9)?,
                accumulated_weight: row.get(10)?,
                p_pct: row.get(11)?,
                acc_p_pct: row.get(12)?,
                cpi: row.get(13)?,
                l1d_cache_hit_rate: row.get(14)?,
                mips: row.get(15)?,
                mcps: row.get(16)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(SourceRowsResponse {
        total,
        limit,
        offset,
        rows,
    })
}

fn query_files(db_path: &Path) -> Result<Vec<FileDto>> {
    let conn = open_readonly(db_path)?;
    let mut stmt = conn.prepare(
        "SELECT file, self_weight, accumulated_weight, sample_count, hot_lines, missing, unresolved, hot_line
         FROM files ORDER BY self_weight DESC, accumulated_weight DESC, file LIMIT 10000",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(FileDto {
                file: row.get(0)?,
                self_weight: row.get(1)?,
                accumulated_weight: row.get(2)?,
                sample_count: row.get::<_, i64>(3)?.max(0) as u64,
                hot_lines: row.get::<_, i64>(4)?.max(0) as u64,
                missing: row.get::<_, i64>(5)?.max(0) as u64,
                unresolved: row.get::<_, i64>(6)?.max(0) as u64,
                hot_line: row.get::<_, i64>(7)?.max(0) as u32,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn query_functions(db_path: &Path) -> Result<Vec<FunctionDto>> {
    let conn = open_readonly(db_path)?;
    let mut stmt = conn.prepare(
        "SELECT function, file, line_start, line_end, module, self_weight, accumulated_weight, sample_count, hot_lines
         FROM functions ORDER BY self_weight DESC, accumulated_weight DESC, function LIMIT 10000",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(FunctionDto {
                function: row.get(0)?,
                file: row.get(1)?,
                line_start: row.get::<_, i64>(2)?.max(0) as u32,
                line_end: row.get::<_, i64>(3)?.max(0) as u32,
                module: row.get(4)?,
                self_weight: row.get(5)?,
                accumulated_weight: row.get(6)?,
                sample_count: row.get::<_, i64>(7)?.max(0) as u64,
                hot_lines: row.get(8)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn query_summary(db_path: &Path) -> Result<serde_json::Value> {
    let conn = open_readonly(db_path)?;
    let text: String = conn.query_row(
        "SELECT value FROM metadata WHERE key='summary'",
        [],
        |row| row.get(0),
    )?;
    Ok(serde_json::from_str(&text)?)
}

fn open_readonly(db_path: &Path) -> Result<Connection> {
    Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("Failed to open '{}'", db_path.display()))
}

fn source_where_clause(query: &SourceQuery) -> (String, Vec<Value>) {
    let mut clauses = Vec::new();
    let mut params = Vec::new();
    if let Some(filter) = query
        .filter
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let like = format!("%{filter}%");
        clauses.push("(file LIKE ? OR function LIKE ? OR code LIKE ?)");
        params.push(Value::Text(like.clone()));
        params.push(Value::Text(like.clone()));
        params.push(Value::Text(like));
    }
    if let Some(cpu) = query
        .cpu
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        clauses.push("cpu LIKE ?");
        params.push(Value::Text(format!("%{cpu}%")));
    }
    if let Some(thread) = query
        .thread
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        clauses.push("thread LIKE ?");
        params.push(Value::Text(format!("%{thread}%")));
    }
    if query.nonzero_only.unwrap_or(false) {
        clauses.push("status LIKE '%NonZero%'");
    }
    if query.function_only.unwrap_or(false) {
        clauses.push("function <> '' AND function <> '<unknown>'");
    }
    if query.missing_only.unwrap_or(false) {
        clauses.push("status LIKE '%Missing%'");
    }
    if query.unresolved_only.unwrap_or(false) {
        clauses.push("status LIKE '%Unresolved%'");
    }
    if clauses.is_empty() {
        (String::new(), params)
    } else {
        (format!(" WHERE {}", clauses.join(" AND ")), params)
    }
}

fn source_order_by(sort: Option<&str>, desc: bool, sampled_first: bool) -> String {
    let column = match sort.unwrap_or("file") {
        "file" => "file",
        "line" => "line",
        "function" => "function",
        "module" => "module",
        "cpu" => "cpu",
        "thread" => "thread",
        "status" => "status",
        "self" | "self_weight" => "self_weight",
        "acc" | "accumulated_weight" => "accumulated_weight",
        _ => "file",
    };
    let direction = if desc { "DESC" } else { "ASC" };
    let sampled_prefix = if sampled_first {
        "CASE WHEN status LIKE '%NonZero%' THEN 0 ELSE 1 END ASC, "
    } else {
        ""
    };
    format!("ORDER BY {sampled_prefix}{column} {direction}, file ASC, line ASC")
}

async fn handle_report_html(State(state): State<AppState>) -> impl IntoResponse {
    let html_path = state
        .db_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("SourceLine.html");
    match fs::read_to_string(&html_path) {
        Ok(html) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            Html(html),
        )
            .into_response(),
        Err(error) => (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            format!(
                "SourceLine.html not found beside '{}': {error}",
                state.db_path.display()
            ),
        )
            .into_response(),
    }
}

async fn handle_summary(State(state): State<AppState>) -> impl IntoResponse {
    json_result(query_summary(&state.db_path))
}

async fn handle_source_lines(
    State(state): State<AppState>,
    Query(query): Query<SourceQuery>,
) -> impl IntoResponse {
    json_result(query_source_lines(&state.db_path, &query))
}

async fn handle_files(State(state): State<AppState>) -> impl IntoResponse {
    json_result(query_files(&state.db_path))
}

async fn handle_functions(State(state): State<AppState>) -> impl IntoResponse {
    json_result(query_functions(&state.db_path))
}

fn json_result<T: Serialize>(result: Result<T>) -> impl IntoResponse {
    match result {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_line_limit_defaults_to_1000() {
        assert_eq!(clamp_limit(None), DEFAULT_PAGE_SIZE);
    }

    #[test]
    fn source_line_limit_is_user_configurable_up_to_10000() {
        assert_eq!(clamp_limit(Some(2500)), 2500);
        assert_eq!(clamp_limit(Some(10000)), MAX_PAGE_SIZE);
        assert_eq!(clamp_limit(Some(25000)), MAX_PAGE_SIZE);
    }

    #[test]
    fn source_line_limit_never_drops_below_one() {
        assert_eq!(clamp_limit(Some(0)), 1);
    }

    #[test]
    fn sampled_first_order_prioritizes_nonzero_rows() {
        let order = source_order_by(None, false, true);

        assert!(
            order.starts_with("ORDER BY CASE WHEN status LIKE '%NonZero%' THEN 0 ELSE 1 END ASC")
        );
    }

    #[tokio::test]
    async fn report_root_serves_html_from_database_directory() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let dir = root.join("target/source_profile_tests/httpd_root");
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("SourceLine.sqlite");
        std::fs::write(
            dir.join("SourceLine.html"),
            "<!doctype html><title>ok</title>",
        )
        .unwrap();

        let response = handle_report_html(State(AppState { db_path }))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
    }

    #[test]
    fn queries_source_lines_with_total_and_limit() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle = crate::source_profile::bundle::SourceProfileBundle::load(
            root.join("fixtures/source_profile/minimal"),
        )
        .unwrap();
        let db_path = root.join("target/source_profile_tests/httpd/SourceLine.sqlite");
        crate::source_profile::report_db::write_report_db(&bundle, &db_path).unwrap();

        let response = query_source_lines(
            &db_path,
            &SourceQuery {
                limit: Some(3),
                ..SourceQuery::default()
            },
        )
        .unwrap();

        assert!(response.total >= 19);
        assert_eq!(response.rows.len(), 3);
        assert!(response.rows.iter().all(|row| !row.file.is_empty()));
    }

    #[test]
    fn function_only_filters_out_rows_without_function() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle = crate::source_profile::bundle::SourceProfileBundle::load(
            root.join("fixtures/source_profile/minimal"),
        )
        .unwrap();
        let db_path = root.join("target/source_profile_tests/httpd_function/SourceLine.sqlite");
        crate::source_profile::report_db::write_report_db(&bundle, &db_path).unwrap();

        let response = query_source_lines(
            &db_path,
            &SourceQuery {
                function_only: Some(true),
                sampled_first: Some(true),
                limit: Some(100),
                ..SourceQuery::default()
            },
        )
        .unwrap();

        assert!(response.rows.iter().all(|row| !row.function.is_empty()));
    }
}
