use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    models::Role,
    AppState,
};

#[derive(Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub role: Role,
    pub exp: usize,
}

pub async fn auth_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let config = state.config.clone();

    let key = DecodingKey::from_secret(config.jwt_secret.as_bytes());
    let token_data = decode::<Claims>(token, &key, &Validation::default())
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Check if token is expired
    let current_timestamp = chrono::Utc::now().timestamp() as usize;
    if token_data.claims.exp < current_timestamp {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let mut request = req;
    request.extensions_mut().insert(Arc::new(token_data.claims));
    Ok(next.run(request).await)
}
