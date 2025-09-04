use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::Response,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use uuid::Uuid;

use crate::{
    auth::verify_access_token,
    entities::{user, User},
    services::token_service::TokenService,
    state::AppState,
};

pub async fn auth_middleware(
    State(app_state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    let token = match auth_header {
        Some(header) => {
            if header.starts_with("Bearer ") {
                &header[7..]
            } else {
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    let claims = match verify_access_token(token, &app_state.config.jwt_secret) {
        Ok(claims) => claims,
        Err(_) => return Err(StatusCode::UNAUTHORIZED),
    };

    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return Err(StatusCode::UNAUTHORIZED),
    };

    let is_blacklisted = match TokenService::is_token_blacklisted(&app_state.db, &claims.jti).await {
        Ok(blacklisted) => blacklisted,
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    if is_blacklisted {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let user = match User::find()
        .filter(user::Column::Id.eq(user_id))
        .one(&app_state.db)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return Err(StatusCode::UNAUTHORIZED),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    request.extensions_mut().insert(user);
    Ok(next.run(request).await)
}
