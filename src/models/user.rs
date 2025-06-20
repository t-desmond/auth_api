use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema, Clone, Debug)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password: String, // Hashed in production
    pub role: Role,
}

#[derive(Serialize, Deserialize, ToSchema, Clone, PartialEq, Debug)]
pub enum Role {
    Admin,
    User,
}

#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, ToSchema, Debug)]
pub struct LoginResponse {
    pub token: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub confirm_password: String,
}

#[derive(Serialize, ToSchema)]
pub struct RegisterResponse {
    pub message: String,
    pub user_id: i32,
    pub username: String,
}