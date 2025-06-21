use axum::{
  extract::{Extension, State},
  http::StatusCode,
  response::IntoResponse,
  Json,
};
use serde_json::json;
use std::sync::Arc;
use utoipa::OpenApi;

use crate::{models::Role, AppState};
use crate::middleware::auth::Claims;

#[derive(OpenApi)]
#[openapi(
  paths(admin_route, admin_dashboard, user_profile)
)]
pub struct ProtectedApi;

#[utoipa::path(
  get,
  path = "/admin",
  responses(
      (status = 200, description = "Admin access granted"),
      (status = 403, description = "Forbidden")
  ),
  security(("api_key" = []))
)]
pub async fn admin_route(Extension(claims): Extension<Arc<Claims>>) -> impl IntoResponse {
  if claims.role == Role::Admin {
      let admin_data = json!({
          "message": "Admin access granted",
          "user": {
              "email": claims.sub,
              "role": claims.role
          }
      });
      (StatusCode::OK, Json(admin_data)).into_response()
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
pub async fn admin_dashboard(Extension(claims): Extension<Arc<Claims>>) -> impl IntoResponse {
  if claims.role == Role::Admin {
      let dashboard_data = json!({
          "message": "Welcome to the admin dashboard",
          "user": {
              "email": claims.sub,
              "role": claims.role
          },
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
pub async fn user_profile(State(state): State<AppState>, Extension(claims): Extension<Arc<Claims>>) -> impl IntoResponse {
  if claims.role == Role::User {
      // Get full user data from state if needed
      let users = state.users.lock().unwrap();
      let user = users.iter().find(|u| u.email == claims.sub);
      
      let profile_data = json!({
          "message": "Welcome to your profile",
          "user": {
              "email": claims.sub,
              "role": claims.role,
              "first_name": user.map(|u| &u.first_name).unwrap_or(&"".to_string()),
              "last_name": user.map(|u| &u.last_name).unwrap_or(&"".to_string()),
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