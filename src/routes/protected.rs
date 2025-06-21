use axum::{
  extract::{Extension, State},
  http::StatusCode,
  response::IntoResponse,
  Json,
};
use serde_json::json;
use std::sync::Arc;
use utoipa::OpenApi;

use crate::{models::{Role, User}, AppState};

#[derive(OpenApi)]
#[openapi(
  paths(admin_route, admin_dashboard, user_profile),
  components(schemas(User))
)]
pub struct ProtectedApi;

#[utoipa::path(
  get,
  path = "/admin",
  responses(
      (status = 200, description = "Admin access granted", body = User),
      (status = 403, description = "Forbidden")
  ),
  security(("api_key" = []))
)]
pub async fn admin_route(Extension(user): Extension<Arc<User>>) -> impl IntoResponse {
  if user.role == Role::Admin {
      (StatusCode::OK, Json(&user)).into_response()
  } else {
      (
          StatusCode::FORBIDDEN,
          Json(json!({"error": "Admin access required"})),
      ).into_response()
  }
}

#[utoipa::path(
  get,
  path = "/admin/dashboard",
  responses(
      (status = 200, description = "Admin dashboard data"),
      (status = 403, description = "Forbidden")
  ),
  security(("api_key" = []))
)]
pub async fn admin_dashboard(Extension(user): Extension<Arc<User>>) -> impl IntoResponse {
  if user.role == Role::Admin {
      let dashboard_data = json!({
          "message": "Welcome to the admin dashboard",
          "user": &user,
          "stats": {
              "total_users": 150,
              "active_sessions": 23,
              "system_status": "healthy"
          }
      });
      (StatusCode::OK, Json(dashboard_data)).into_response()
  } else {
      (
          StatusCode::FORBIDDEN,
          Json(json!({"error": "Admin access required"})),
      ).into_response()
  }
}

#[utoipa::path(
  get,
  path = "/user/profile",
  responses(
      (status = 200, description = "User profile data"),
      (status = 403, description = "Forbidden - User access required")
  ),
  security(("api_key" = []))
)]
pub async fn user_profile(State(state): State<AppState>, Extension(user): Extension<Arc<User>>) -> impl IntoResponse {
  if user.role == Role::User {
      let profile_data = json!({
          "message": "Welcome to your profile",
          "user": {
              "id": user.id,
              "username": &user.email,
              "role": &user.role
          },
          "preferences": {
              "theme": "light",
              "notifications": true,
              "language": "en"
          },
          "activity": {
              "last_login": "2024-01-15T10:30:00Z",
              "login_count": 42
          }
      });
      (StatusCode::OK, Json(profile_data)).into_response()
  } else {
      (
          StatusCode::FORBIDDEN,
          Json(json!({"error": "User access required"})),
      ).into_response()
  }
}