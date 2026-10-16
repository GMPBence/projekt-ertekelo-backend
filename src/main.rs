use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bcrypt::{hash, verify};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::header::ContentType,
    transport::smtp::{authentication::Credentials, client::Tls},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, MySqlPool};
use std::{env, net::SocketAddr};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use url::Url;
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    db: MySqlPool,
    jwt_secret: String,
    email_service: Option<EmailService>,
}

#[derive(Clone)]
struct EmailService {
    mailer: AsyncSmtpTransport<Tokio1Executor>,
    from: String,
}

impl EmailService {
    fn from_env() -> Result<Option<Self>> {
        let keys = ["SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM"];
        let configured = keys
            .iter()
            .filter(|key| env::var(key).is_ok_and(|value| !value.trim().is_empty()))
            .count();
        if configured == 0 {
            return Ok(None);
        }
        if configured != keys.len() {
            bail!("SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD and SMTP_FROM must all be set");
        }

        let host = env::var("SMTP_HOST")?;
        let username = env::var("SMTP_USERNAME")?;
        let password = env::var("SMTP_PASSWORD")?;
        let from = env::var("SMTP_FROM")?;
        let port = env::var("SMTP_PORT")
            .unwrap_or_else(|_| "465".to_owned())
            .parse::<u16>()
            .context("SMTP_PORT must be a valid port number")?;
        let tls = Tls::Wrapper(
            lettre::transport::smtp::client::TlsParameters::builder(host.clone()).build()?,
        );
        let mailer = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host)
            .port(port)
            .tls(tls)
            .credentials(Credentials::new(username, password))
            .build();
        Ok(Some(Self { mailer, from }))
    }

    async fn send_recovery_code(&self, recipient: &str, code: &str) -> Result<()> {
        let message = Message::builder()
            .from(self.from.parse()?)
            .to(recipient.parse()?)
            .subject("Értékelő – Jelszó visszaállítás")
            .header(ContentType::TEXT_HTML)
            .body(format!(
                "<!doctype html><html lang=\"hu\"><meta charset=\"utf-8\"><p>A jelszó-visszaállítási kódod:</p><p style=\"font-size:24px;font-weight:bold;letter-spacing:4px\">{code}</p><p>A kód 15 percig érvényes. Ha nem te kérted, hagyd figyelmen kívül ezt az emailt.</p></html>"
            ))?;
        self.mailer.send(message).await?;
        Ok(())
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: &'static str,
}

impl ApiError {
    fn new(status: StatusCode, message: &'static str) -> Self {
        Self { status, message }
    }

    fn bad_request(message: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "Belső szerverhiba.")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

#[derive(Deserialize)]
struct RegisterRequest {
    email: String,
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct RecoverRequest {
    email: String,
}

#[derive(Deserialize)]
struct RecoverCompleteRequest {
    email: String,
    token: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    email: String,
    username: String,
    exp: usize,
}

#[derive(Serialize, Deserialize)]
struct PublicUser {
    id: String,
    email: String,
    username: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    user: PublicUser,
}

#[derive(Deserialize)]
struct CreateProjectRequest {
    title: String,
    authors: String,
    description: Option<String>,
    website_url: Option<String>,
}

#[derive(Deserialize)]
struct SaveEvaluationRequest {
    grade: Option<u8>,
    theme: Option<u8>,
    design: Option<u8>,
    animations: Option<u8>,
    javascript: Option<u8>,
    feedback: Option<String>,
    #[serde(default = "default_published")]
    published: bool,
}

fn default_published() -> bool {
    true
}

#[derive(Serialize, FromRow)]
struct Evaluation {
    grade: Option<u8>,
    theme: Option<u8>,
    design: Option<u8>,
    animations: Option<u8>,
    javascript: Option<u8>,
    feedback: Option<String>,
    published: bool,
}

#[derive(FromRow)]
struct ProjectRow {
    id: String,
    title: String,
    authors: String,
    description: Option<String>,
    website_url: Option<String>,
    created_at: DateTime<Utc>,
    evaluation_grade: Option<u8>,
    evaluation_theme: Option<u8>,
    evaluation_design: Option<u8>,
    evaluation_animations: Option<u8>,
    evaluation_javascript: Option<u8>,
    evaluation_feedback: Option<String>,
    evaluation_published: Option<bool>,
}

#[derive(Serialize)]
struct ProjectResponse {
    id: String,
    title: String,
    authors: String,
    description: Option<String>,
    website_url: Option<String>,
    created_at: DateTime<Utc>,
    evaluation: Option<Evaluation>,
}

impl From<ProjectRow> for ProjectResponse {
    fn from(row: ProjectRow) -> Self {
        let evaluation = row.evaluation_published.map(|published| Evaluation {
            grade: row.evaluation_grade,
            theme: row.evaluation_theme,
            design: row.evaluation_design,
            animations: row.evaluation_animations,
            javascript: row.evaluation_javascript,
            feedback: row.evaluation_feedback,
            published,
        });
        Self {
            id: row.id,
            title: row.title,
            authors: row.authors,
            description: row.description,
            website_url: row.website_url,
            created_at: row.created_at,
            evaluation,
        }
    }
}

fn validate_email(email: &str) -> bool {
    email.len() <= 254
        && email.contains('@')
        && email.rsplit_once('@').is_some_and(|(name, domain)| {
            !name.is_empty()
                && !name.contains('@')
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        })
        && !email.chars().any(char::is_whitespace)
}

fn validate_password(password: &str) -> bool {
    (8..=72).contains(&password.len())
}

fn validate_website_url(value: &str) -> bool {
    value.len() <= 2048
        && Url::parse(value).is_ok_and(|url| matches!(url.scheme(), "http" | "https"))
}

fn api_error_from_sql(error: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(database_error) = &error
        && database_error.code().as_deref() == Some("1062")
    {
        return ApiError::new(
            StatusCode::CONFLICT,
            "Email vagy felhasználónév már használatban van.",
        );
    }
    eprintln!("[DB ERROR] {error}");
    ApiError::internal()
}

fn make_login_response(
    state: &AppState,
    id: String,
    email: String,
    username: String,
) -> Result<LoginResponse, ApiError> {
    let expiration = (Utc::now() + Duration::hours(24)).timestamp() as usize;
    let claims = Claims {
        sub: id.clone(),
        email: email.clone(),
        username: username.clone(),
        exp: expiration,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .map_err(|error| {
        eprintln!("[JWT ERROR] {error}");
        ApiError::internal()
    })?;
    Ok(LoginResponse {
        token,
        user: PublicUser {
            id,
            email,
            username,
        },
    })
}

fn authenticated_user(headers: &HeaderMap, state: &AppState) -> Result<Claims, ApiError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "Jelentkezz be a folytatáshoz."))?;
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|_| {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "A munkamenet lejárt. Jelentkezz be újra.",
        )
    })
}

async fn health() -> &'static str {
    "ok"
}

async fn register(
    State(state): State<AppState>,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let email = request.email.trim().to_lowercase();
    let username = request.username.trim().to_owned();
    if !validate_email(&email)
        || !(3..=50).contains(&username.chars().count())
        || !validate_password(&request.password)
    {
        return Err(ApiError::bad_request(
            "Érvénytelen email, felhasználónév vagy jelszó. A jelszó 8–72 bájtos legyen.",
        ));
    }
    let password_hash = hash(&request.password, 12).map_err(|error| {
        eprintln!("[PASSWORD ERROR] {error}");
        ApiError::internal()
    })?;
    let id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users (id, email, username, password_hash) VALUES (?, ?, ?, ?)")
        .bind(&id)
        .bind(&email)
        .bind(&username)
        .bind(password_hash)
        .execute(&state.db)
        .await
        .map_err(api_error_from_sql)?;
    make_login_response(&state, id, email, username).map(Json)
}

async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let email = request.email.trim().to_lowercase();
    if !validate_email(&email) || !validate_password(&request.password) {
        return Err(ApiError::bad_request("Hibás email cím vagy jelszó."));
    }
    let user = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT id, email, username, password_hash FROM users WHERE email = ?",
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await
    .map_err(api_error_from_sql)?
    .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "Hibás email cím vagy jelszó."))?;
    let password_matches = verify(&request.password, &user.3).map_err(|error| {
        eprintln!("[PASSWORD VERIFY ERROR] {error}");
        ApiError::internal()
    })?;
    if !password_matches {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "Hibás email cím vagy jelszó.",
        ));
    }
    make_login_response(&state, user.0, user.1, user.2).map(Json)
}

async fn recover(
    State(state): State<AppState>,
    Json(request): Json<RecoverRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let email = request.email.trim().to_lowercase();
    if !validate_email(&email) {
        return Err(ApiError::bad_request("Adj meg egy érvényes email címet."));
    }
    let email_service = state.email_service.as_ref().ok_or_else(|| {
        eprintln!("[EMAIL ERROR] SMTP is not configured");
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "A jelszó-visszaállító email szolgáltatás nincs beállítva.",
        )
    })?;
    let user = sqlx::query_as::<_, (String, String)>("SELECT id, email FROM users WHERE email = ?")
        .bind(&email)
        .fetch_optional(&state.db)
        .await
        .map_err(api_error_from_sql)?;
    if let Some((user_id, stored_email)) = user {
        let code = format!("{:09}", Uuid::new_v4().as_u128() % 1_000_000_000);
        let token_hash = hex::encode(Sha256::digest(code.as_bytes()));
        let expires_at = Utc::now() + Duration::minutes(15);
        sqlx::query(
            "INSERT INTO recovery_tokens (user_id, token_hash, attempts, expires_at) VALUES (?, ?, 0, ?) \
             ON DUPLICATE KEY UPDATE token_hash = VALUES(token_hash), attempts = 0, expires_at = VALUES(expires_at)",
        )
        .bind(user_id)
        .bind(token_hash)
        .bind(expires_at)
        .execute(&state.db)
        .await
        .map_err(api_error_from_sql)?;
        if let Err(error) = email_service.send_recovery_code(&stored_email, &code).await {
            eprintln!("[EMAIL ERROR] Could not send recovery code: {error:#}");
            return Err(ApiError::internal());
        }
    }
    Ok(Json(
        serde_json::json!({ "message": "Ha a címhez tartozik fiók, elküldtük a kódot." }),
    ))
}

async fn recover_complete(
    State(state): State<AppState>,
    Json(request): Json<RecoverCompleteRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let email = request.email.trim().to_lowercase();
    let token = request.token.trim();
    if !validate_email(&email)
        || !validate_password(&request.password)
        || !is_nine_digit_code(token)
    {
        return Err(ApiError::bad_request(
            "Adj meg érvényes emailt, 9 jegyű kódot és legalább 8 karakteres jelszót.",
        ));
    }
    let token_hash = hex::encode(Sha256::digest(token.as_bytes()));
    let password_hash = hash(&request.password, 12).map_err(|error| {
        eprintln!("[PASSWORD ERROR] {error}");
        ApiError::internal()
    })?;
    let mut transaction = state.db.begin().await.map_err(api_error_from_sql)?;
    let recovery = sqlx::query_as::<_, (String, String, DateTime<Utc>, u8)>(
        "SELECT r.user_id, r.token_hash, r.expires_at, r.attempts FROM recovery_tokens r \
         JOIN users u ON u.id = r.user_id WHERE u.email = ? FOR UPDATE",
    )
    .bind(&email)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(api_error_from_sql)?
    .ok_or_else(|| ApiError::bad_request("A kód érvénytelen vagy lejárt."))?;
    let (user_id, stored_token_hash, expires_at, attempts) = recovery;
    if expires_at <= Utc::now() {
        sqlx::query("DELETE FROM recovery_tokens WHERE user_id = ?")
            .bind(&user_id)
            .execute(&mut *transaction)
            .await
            .map_err(api_error_from_sql)?;
        transaction.commit().await.map_err(api_error_from_sql)?;
        return Err(ApiError::bad_request("A kód érvénytelen vagy lejárt."));
    }
    if attempts >= 5 {
        return Err(ApiError::bad_request(
            "Túl sok hibás próbálkozás. Kérj új helyreállító kódot.",
        ));
    }
    if stored_token_hash != token_hash {
        sqlx::query("UPDATE recovery_tokens SET attempts = attempts + 1 WHERE user_id = ?")
            .bind(&user_id)
            .execute(&mut *transaction)
            .await
            .map_err(api_error_from_sql)?;
        transaction.commit().await.map_err(api_error_from_sql)?;
        return Err(ApiError::bad_request("A kód érvénytelen vagy lejárt."));
    }
    sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(password_hash)
        .bind(&user_id)
        .execute(&mut *transaction)
        .await
        .map_err(api_error_from_sql)?;
    sqlx::query("DELETE FROM recovery_tokens WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(api_error_from_sql)?;
    transaction.commit().await.map_err(api_error_from_sql)?;
    Ok(Json(
        serde_json::json!({ "message": "A jelszó sikeresen frissült." }),
    ))
}

fn is_nine_digit_code(code: &str) -> bool {
    code.len() == 9 && code.bytes().all(|byte| byte.is_ascii_digit())
}

const PROJECT_SELECT: &str = "SELECT p.id, p.title, p.authors, p.description, p.website_url, p.created_at, \
    e.grade AS evaluation_grade, e.theme AS evaluation_theme, e.design AS evaluation_design, \
    e.animations AS evaluation_animations, e.javascript AS evaluation_javascript, \
    e.feedback AS evaluation_feedback, e.published AS evaluation_published \
    FROM projects p LEFT JOIN evaluations e ON e.project_id = p.id AND e.user_id = ?";

async fn list_projects(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = authenticated_user(&headers, &state)?;
    let query = format!("{PROJECT_SELECT} ORDER BY p.created_at DESC");
    let projects = sqlx::query_as::<_, ProjectRow>(&query)
        .bind(user.sub)
        .fetch_all(&state.db)
        .await
        .map_err(api_error_from_sql)?
        .into_iter()
        .map(ProjectResponse::from)
        .collect::<Vec<_>>();
    Ok(Json(serde_json::json!({ "projects": projects })))
}

async fn get_project(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ProjectResponse>, ApiError> {
    let user = authenticated_user(&headers, &state)?;
    let query = format!("{PROJECT_SELECT} WHERE p.id = ?");
    let project = sqlx::query_as::<_, ProjectRow>(&query)
        .bind(user.sub)
        .bind(project_id)
        .fetch_optional(&state.db)
        .await
        .map_err(api_error_from_sql)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "A projekt nem található."))?;
    Ok(Json(ProjectResponse::from(project)))
}

async fn create_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateProjectRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let user = authenticated_user(&headers, &state)?;
    let title = request.title.trim();
    let authors = request.authors.trim();
    let description = request
        .description
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let website_url = request
        .website_url
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if title.is_empty()
        || title.chars().count() > 255
        || authors.is_empty()
        || authors.chars().count() > 500
    {
        return Err(ApiError::bad_request(
            "A projekt neve (max. 255) és készítői (max. 500) kötelezők.",
        ));
    }
    if description
        .as_ref()
        .is_some_and(|value| value.chars().count() > 5000)
    {
        return Err(ApiError::bad_request(
            "A projekt leírása legfeljebb 5000 karakter lehet.",
        ));
    }
    if website_url
        .as_ref()
        .is_some_and(|value| !validate_website_url(value))
    {
        return Err(ApiError::bad_request(
            "A webcím http:// vagy https:// kezdetű legyen.",
        ));
    }
    let project_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO projects (id, title, authors, description, website_url, created_by) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&project_id)
    .bind(title)
    .bind(authors)
    .bind(description)
    .bind(website_url)
    .bind(user.sub)
    .execute(&state.db)
    .await
    .map_err(api_error_from_sql)?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "id": project_id })),
    ))
}

async fn save_evaluation(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<SaveEvaluationRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = authenticated_user(&headers, &state)?;
    let scores = [
        request.grade,
        request.theme,
        request.design,
        request.animations,
        request.javascript,
    ];
    if scores
        .iter()
        .flatten()
        .any(|score| !(1..=5).contains(score))
        || (request.published && scores.iter().any(Option::is_none))
        || request
            .feedback
            .as_ref()
            .is_some_and(|value| value.chars().count() > 5000)
    {
        return Err(ApiError::bad_request(
            "Az érdemjegy és minden kritériumpont 1–5 közötti, a visszajelzés legfeljebb 5000 karakter lehet.",
        ));
    }
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM projects WHERE id = ?)")
        .bind(&project_id)
        .fetch_one(&state.db)
        .await
        .map_err(api_error_from_sql)?;
    if !exists {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "A projekt nem található.",
        ));
    }
    sqlx::query(
        "INSERT INTO evaluations (id, project_id, user_id, grade, theme, design, animations, javascript, feedback, published) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE grade = VALUES(grade), theme = VALUES(theme), design = VALUES(design), \
         animations = VALUES(animations), javascript = VALUES(javascript), feedback = VALUES(feedback), published = VALUES(published)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(project_id)
    .bind(user.sub)
    .bind(request.grade)
    .bind(request.theme)
    .bind(request.design)
    .bind(request.animations)
    .bind(request.javascript)
    .bind(request.feedback)
    .bind(request.published)
    .execute(&state.db)
    .await
    .map_err(api_error_from_sql)?;
    Ok(Json(
        serde_json::json!({ "message": "Az értékelés mentése sikerült." }),
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let jwt_secret = env::var("JWT_SECRET").context("JWT_SECRET must be configured")?;
    if jwt_secret.len() < 32 {
        bail!("JWT_SECRET must contain at least 32 characters");
    }
    let database_url = env::var("DATABASE_URL").context("DATABASE_URL must be configured")?;
    let db = MySqlPool::connect(&database_url)
        .await
        .context("Could not connect to MySQL")?;
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .context("Database migration failed")?;

    let email_service = EmailService::from_env()?;
    let state = AppState {
        db,
        jwt_secret,
        email_service,
    };
    let origins = env::var("CORS_ORIGINS")
        .unwrap_or_else(|_| "*".to_owned())
        .split(',')
        .map(|origin| {
            origin
                .trim()
                .parse::<HeaderValue>()
                .context("Invalid CORS origin")
        })
        .collect::<Result<Vec<_>>>()?;
    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);
    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/auth/register", post(register))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/recover", post(recover))
        .route("/api/v1/auth/recover/complete", post(recover_complete))
        .route("/api/v1/projects", get(list_projects).post(create_project))
        .route("/api/v1/projects/{id}", get(get_project))
        .route("/api/v1/projects/{id}/evaluations", post(save_evaluation))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    let port = env::var("SERVER_PORT").unwrap_or_else(|_| "8080".to_owned());
    let address: SocketAddr = format!("0.0.0.0:{port}").parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    println!("projekt-ertekelo API listening on {address}");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{is_nine_digit_code, validate_email, validate_password, validate_website_url};

    #[test]
    fn validates_email_shape() {
        assert!(validate_email("tanar@iskola.hu"));
        assert!(!validate_email("invalid-email"));
        assert!(!validate_email(" tanar@iskola.hu "));
    }

    #[test]
    fn enforces_bcrypt_password_bounds() {
        assert!(!validate_password("short"));
        assert!(validate_password("long-enough"));
        assert!(!validate_password(&"x".repeat(73)));
    }

    #[test]
    fn accepts_only_nine_digit_recovery_codes() {
        assert!(is_nine_digit_code("123456789"));
        assert!(!is_nine_digit_code("12345"));
        assert!(!is_nine_digit_code("12345678a"));
    }

    #[test]
    fn accepts_only_http_project_urls() {
        assert!(validate_website_url("https://example.com/project"));
        assert!(!validate_website_url("javascript:alert(1)"));
        assert!(!validate_website_url("not a URL"));
    }
}
