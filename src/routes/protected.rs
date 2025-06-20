use axum::{
  extract::Extension,
  http::StatusCode,
  response::IntoResponse,
  Json,
};
use serde_json::json;
use std::sync::Arc;
use utoipa::OpenApi;

use crate::models::{Role, User};

#[derive(OpenApi)]
#[openapi(
  paths(admin_route),
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
      (StatusCode::OK, Json(user)).into_response()
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