use axum::{http::StatusCode, response::IntoResponse, Json};
use dotenv::dotenv;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::json;
use utoipa::OpenApi;

use crate::middleware::auth::Claims;
use crate::models::{LoginRequest, LoginResponse, Role};

#[derive(OpenApi)]
#[openapi(paths(login), components(schemas(LoginRequest, LoginResponse)))]
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
  dotenv().ok();
    // In production, verify against a database
    if payload.username == "admin" && payload.password == "password" {
        let claims = Claims {
            sub: payload.username.clone(),
            role: Role::Admin,
            exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
        };

        let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        
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
                    Json(json!({"error": "Failed to generate token"})),
                ).into_response();
            }
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "Invalid Credentials"})),
    )
        .into_response()
}
