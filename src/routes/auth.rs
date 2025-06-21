use axum::extract::State;
use axum::{http::StatusCode, response::IntoResponse, Json};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::json;
use utoipa::OpenApi;

use crate::middleware::auth::Claims;
use crate::models::{LoginRequest, LoginResponse, RegisterRequest, RegisterResponse, Role, User};
use crate::AppState;

#[derive(OpenApi)]
#[openapi(
    paths(login, register),
    components(schemas(LoginRequest, LoginResponse, RegisterRequest, RegisterResponse))
)]
pub struct AuthApi;

#[utoipa::path(
    post,
    path = "/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = LoginResponse),
        (status = 401, description = "Invalid credentials")
    )
)]
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    let users = state.users.lock().unwrap();

    // Check if the user exists
    let user = users.iter().find(|user| user.email == payload.email);

    if user.is_none() || bcrypt::verify(payload.password.as_bytes(), &user.unwrap().password).ok() != Some(true){
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid credentials"})),
        )
            .into_response();
    }

    let claims = Claims {
        sub: payload.email.clone(),
        role: user.unwrap().role.clone(),
        exp: (chrono::Utc::now() + chrono::Duration::days(1)).timestamp() as usize,
    };

    let config = state.config.clone();

    let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());

    let token = encode(&Header::default(), &claims, &key).unwrap();

    (
        StatusCode::OK,
        Json(LoginResponse { token }),
    )
        .into_response()
}

#[utoipa::path(
    post,
    path = "/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "User registered successfully", body = RegisterResponse),
        (status = 400, description = "Bad request")
    )
)]
pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    // In production, verify against a database
    if payload.email.is_empty() || payload.password.is_empty() || payload.first_name.is_empty() || payload.last_name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "All fields are required"})),
        )
            .into_response();
    }

    let hashed_password =
        bcrypt::hash(payload.password.as_bytes(), bcrypt::DEFAULT_COST)
        .unwrap();

    let mut users = state.users.lock().unwrap();

    let new_user = User {
        id: users.len() as u32 + 1,
        email: payload.email.clone(),
        password: hashed_password.to_string(),
        role: Role::User,
        first_name: payload.first_name.clone(),
        last_name: payload.last_name.clone(),
    };

    let user_id = new_user.id;
    users.push(new_user);

    (
        StatusCode::CREATED,
        Json(RegisterResponse {
            id: user_id,
            first_name: payload.first_name,
            last_name: payload.last_name,
            email: payload.email,
        }),
    )
        .into_response()
}
