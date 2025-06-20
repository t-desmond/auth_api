use axum::{http::StatusCode, response::IntoResponse, Json};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::json;
use utoipa::OpenApi;

use crate::middleware::auth::Claims;
use crate::models::{LoginRequest, LoginResponse, RegisterRequest, RegisterResponse, Role};

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
pub async fn login(Json(payload): Json<LoginRequest>) -> impl IntoResponse {
    // In production, verify against a database
    if payload.username == "admin" && payload.password == "password" {
        let claims = Claims {
            sub: payload.username.clone(),
            role: Role::Admin,
            exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
        };

        let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key".to_string());
        
        match encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(jwt_secret.as_bytes()),
        ) {
            Ok(token) => {
                return (StatusCode::OK, Json(LoginResponse { token })).into_response();
            }
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Token generation failed"})),
                ).into_response();
            }
        }
    } else if payload.username == "user" && payload.password == "password" {
        let claims = Claims {
            sub: payload.username.clone(),
            role: Role::User,
            exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
        };

        let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key".to_string());
        
        match encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(jwt_secret.as_bytes()),
        ) {
            Ok(token) => {
                return (StatusCode::OK, Json(LoginResponse { token })).into_response();
            }
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Token generation failed"})),
                ).into_response();
            }
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "Invalid credentials"})),
    ).into_response()
}

#[utoipa::path(
    post,
    path = "/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "User registered successfully", body = RegisterResponse),
        (status = 400, description = "Bad request - validation errors"),
        (status = 409, description = "Username already exists")
    )
)]
pub async fn register(Json(payload): Json<RegisterRequest>) -> impl IntoResponse {
    // Validate input
    if payload.username.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Username cannot be empty"})),
        ).into_response();
    }

    if payload.password.len() < 6 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Password must be at least 6 characters long"})),
        ).into_response();
    }

    if payload.password != payload.confirm_password {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Passwords do not match"})),
        ).into_response();
    }

    // In production, check if username already exists in database
    if payload.username == "admin" || payload.username == "test" || payload.username == "user" {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "Username already exists"})),
        ).into_response();
    }

    let user_id = 42;

    let response = RegisterResponse {
        message: "User registered successfully".to_string(),
        user_id,
        username: payload.username,
    };

    (StatusCode::CREATED, Json(response)).into_response()
}