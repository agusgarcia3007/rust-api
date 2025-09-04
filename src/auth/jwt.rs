use anyhow::Result;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::{distributions::Alphanumeric, Rng};
use uuid::Uuid;

use crate::dto::{Claims, RefreshClaims};
use crate::entities::user;

pub fn create_access_token(user: &user::Model, secret: &str) -> Result<(String, String)> {
    let now = Utc::now();
    let expire = now + Duration::minutes(15);
    let jti = Uuid::new_v4().to_string();

    let claims = Claims {
        sub: user.id.to_string(),
        email: user.email.clone(),
        name: user.name.clone(),
        jti: jti.clone(),
        iat: now.timestamp() as usize,
        exp: expire.timestamp() as usize,
        token_type: "access".to_string(),
    };

    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("access_token".to_string());

    let token = encode(&header, &claims, &EncodingKey::from_secret(secret.as_ref()))?;

    Ok((token, jti))
}

pub fn create_refresh_token(user_id: Uuid, secret: &str) -> Result<String> {
    let now = Utc::now();
    let expire = now + Duration::days(30);
    let jti = Uuid::new_v4().to_string();

    let claims = RefreshClaims {
        sub: user_id.to_string(),
        jti,
        iat: now.timestamp() as usize,
        exp: expire.timestamp() as usize,
        token_type: "refresh".to_string(),
    };

    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("refresh_token".to_string());

    let token = encode(&header, &claims, &EncodingKey::from_secret(secret.as_ref()))?;

    Ok(token)
}

pub fn verify_access_token(token: &str, secret: &str) -> Result<Claims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = 30;
    validation.required_spec_claims.insert("exp".to_string());
    validation.required_spec_claims.insert("iat".to_string());
    validation.required_spec_claims.insert("sub".to_string());
    validation.required_spec_claims.insert("jti".to_string());

    let token_data = decode::<Claims>(token, &DecodingKey::from_secret(secret.as_ref()), &validation)?;

    if token_data.claims.token_type != "access" {
        return Err(anyhow::anyhow!("Invalid token type"));
    }

    Ok(token_data.claims)
}

pub fn verify_refresh_token(token: &str, secret: &str) -> Result<RefreshClaims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = 30;
    validation.required_spec_claims.insert("exp".to_string());
    validation.required_spec_claims.insert("iat".to_string());
    validation.required_spec_claims.insert("sub".to_string());
    validation.required_spec_claims.insert("jti".to_string());

    let token_data = decode::<RefreshClaims>(token, &DecodingKey::from_secret(secret.as_ref()), &validation)?;

    if token_data.claims.token_type != "refresh" {
        return Err(anyhow::anyhow!("Invalid token type"));
    }

    Ok(token_data.claims)
}

pub fn generate_secure_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

pub fn hash_password(password: &str) -> Result<String> {
    let cost = if cfg!(debug_assertions) { 4 } else { bcrypt::DEFAULT_COST };
    let hashed = bcrypt::hash(password, cost)?;
    Ok(hashed)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let is_valid = bcrypt::verify(password, hash)?;
    Ok(is_valid)
}
