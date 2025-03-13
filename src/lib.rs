use chrono::{DateTime, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    pub iss: String, // issuer (JWTの発行者)
    pub sub: String, // subject (ユーザーの識別子)
    pub iat: i64,    // Issued At (発行日時)
    pub exp: i64,    // expiration time (トークンの有効期限)
    pub jti: String, // JWT ID (JWTの一意な識別子)
}

impl Claims {
    pub fn new(sub: &str, duration_seconds: i64) -> Self {
        let current_time: DateTime<Utc> = Utc::now();
        Self {
            iss: env!("CARGO_PKG_NAME").to_string(),
            sub: sub.to_string(),
            iat: current_time.timestamp(),
            exp: current_time.timestamp() + duration_seconds,
            jti: uuid::Uuid::new_v4().to_string(),
        }
    }
}

static SECRET: LazyLock<String> = LazyLock::new(|| uuid::Uuid::new_v4().to_string());

pub fn encode(claims: &Claims) -> Result<String, jsonwebtoken::errors::Error> {
    Ok(jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(SECRET.to_string().as_bytes()),
    )?)
}

pub fn decode(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let claims: Claims = jsonwebtoken::decode::<Claims>(
        &token,
        &DecodingKey::from_secret(SECRET.to_string().as_ref()),
        &Validation::default(),
    )?
    .claims;

    // 有効期限のチェック(デフォルトでチェックされるはずなのだが...)
    if claims.exp < Utc::now().timestamp() {
        return Err(jsonwebtoken::errors::ErrorKind::ExpiredSignature.into());
    }

    Ok(claims)
}
