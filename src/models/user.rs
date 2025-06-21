use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema, Clone, Debug)]
pub struct User {
    pub id: u32,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub password: String,
    pub role: Role,
}

#[derive(Serialize, Deserialize, ToSchema, Clone, PartialEq, Debug)]
pub enum Role {
    Admin,
    User,
}

#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, ToSchema, Debug)]
pub struct LoginResponse {
    pub token: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct RegisterRequest {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub password: String,
}

#[derive(Serialize, ToSchema)]
pub struct RegisterResponse {
    pub id: u32,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
}