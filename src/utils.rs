use dotenv::dotenv;

pub struct Config {
    pub jwt_salt: String,
    pub jwt_secret: String,
    pub jwt_exp: String,
}

pub fn load_env() -> Config {
    dotenv().ok();
    let jwt_salt = std::env::var("JWT_SALT").expect("JWT_SALT must be set");
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let jwt_exp = std::env::var("JWT_EXP").expect("JWT_EXP must be set");

    Config {
        jwt_salt,
        jwt_secret,
        jwt_exp,
    }
}