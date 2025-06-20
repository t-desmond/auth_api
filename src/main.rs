use axum::{
    routing::{get, post},
    Router,
};
use tower_http::cors::CorsLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub mod middleware;
pub mod models;
pub mod routes;

use crate::{
    middleware::auth::auth_middleware,
    routes::{auth, protected},
};

#[tokio::main]
async fn main() {
    #[derive(OpenApi)]
    #[openapi(
        info(title = "Auth API", description = "A simple auth API with registration and admin routes"),
        paths(
            auth::login, 
            auth::register, 
            protected::admin_route, 
            protected::admin_dashboard
        ),
        components(schemas(
            models::User,
            models::Role,
            models::LoginRequest,
            models::LoginResponse,
            models::RegisterRequest,
            models::RegisterResponse
        ))
    )]
    struct ApiDoc;

    let app = Router::new()
        .route("/admin", get(protected::admin_route))
        .route("/admin/dashboard", get(protected::admin_dashboard))
        .layer(axum::middleware::from_fn(auth_middleware))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/login", post(auth::login))
        .route("/register", post(auth::register))
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server running on http://0.0.0.0:3000");
    println!("Swagger UI available at http://0.0.0.0:3000/swagger-ui");
    axum::serve(listener, app).await.unwrap();
}