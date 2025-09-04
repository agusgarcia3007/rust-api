use anyhow::Result;
use chrono::{Duration, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

use crate::{
    auth::{create_access_token, create_refresh_token, generate_secure_token, verify_refresh_token},
    entities::{session, token_blacklist, user, Session, TokenBlacklist, User},
};

pub struct TokenService;

impl TokenService {
    pub async fn create_session(
        db: &DatabaseConnection,
        user: &user::Model,
        jwt_secret: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(String, String, String)> {
        let (access_token, access_jti) = create_access_token(user, jwt_secret)?;
        let refresh_token_jwt = create_refresh_token(user.id, jwt_secret)?;
        let refresh_token = generate_secure_token();

        let expires_at = Utc::now() + Duration::days(30);

        let session = session::ActiveModel {
            user_id: Set(user.id),
            refresh_token: Set(refresh_token.clone()),
            access_token_jti: Set(access_jti),
            expires_at: Set(expires_at),
            ip_address: Set(ip_address),
            user_agent: Set(user_agent),
            ..Default::default()
        };

        session.insert(db).await?;

        Ok((access_token, refresh_token_jwt, refresh_token))
    }

    pub async fn refresh_access_token(
        db: &DatabaseConnection,
        refresh_token_jwt: &str,
        refresh_token: &str,
        jwt_secret: &str,
    ) -> Result<String> {
        let refresh_claims = verify_refresh_token(refresh_token_jwt, jwt_secret)?;
        let user_id = Uuid::parse_str(&refresh_claims.sub)?;

        let session = Session::find()
            .filter(session::Column::RefreshToken.eq(refresh_token))
            .filter(session::Column::UserId.eq(user_id))
            .filter(session::Column::IsActive.eq(true))
            .filter(session::Column::ExpiresAt.gt(Utc::now()))
            .one(db)
            .await?;

        let session = session.ok_or_else(|| anyhow::anyhow!("Invalid refresh token"))?;

        let user = User::find_by_id(session.user_id).one(db).await?;
        let user = user.ok_or_else(|| anyhow::anyhow!("User not found"))?;

        let (new_access_token, new_access_jti) = create_access_token(&user, jwt_secret)?;

        let mut session: session::ActiveModel = session.into();
        session.access_token_jti = Set(new_access_jti);
        session.last_used_at = Set(Utc::now());
        session.update(db).await?;

        Ok(new_access_token)
    }

    pub async fn revoke_token(
        db: &DatabaseConnection,
        token_jti: &str,
        user_id: Uuid,
        reason: Option<String>,
    ) -> Result<()> {
        let expires_at = Utc::now() + Duration::hours(24);

        let blacklist_entry = token_blacklist::ActiveModel {
            token_jti: Set(token_jti.to_string()),
            user_id: Set(user_id),
            expires_at: Set(expires_at),
            reason: Set(reason),
            ..Default::default()
        };

        blacklist_entry.insert(db).await?;
        Ok(())
    }

    pub async fn revoke_all_user_sessions(
        db: &DatabaseConnection,
        user_id: Uuid,
        reason: Option<String>,
    ) -> Result<()> {
        let sessions = Session::find()
            .filter(session::Column::UserId.eq(user_id))
            .filter(session::Column::IsActive.eq(true))
            .all(db)
            .await?;

        for session in sessions {
            Self::revoke_token(db, &session.access_token_jti, user_id, reason.clone()).await?;

            let mut session: session::ActiveModel = session.into();
            session.is_active = Set(false);
            session.update(db).await?;
        }

        Ok(())
    }

    pub async fn is_token_blacklisted(
        db: &DatabaseConnection,
        token_jti: &str,
    ) -> Result<bool> {
        let blacklisted = TokenBlacklist::find()
            .filter(token_blacklist::Column::TokenJti.eq(token_jti))
            .filter(token_blacklist::Column::ExpiresAt.gt(Utc::now()))
            .one(db)
            .await?;

        Ok(blacklisted.is_some())
    }

    pub async fn cleanup_expired_tokens(db: &DatabaseConnection) -> Result<()> {
        TokenBlacklist::delete_many()
            .filter(token_blacklist::Column::ExpiresAt.lt(Utc::now()))
            .exec(db)
            .await?;

        Session::delete_many()
            .filter(session::Column::ExpiresAt.lt(Utc::now()))
            .exec(db)
            .await?;

        Ok(())
    }

    pub async fn logout_session(
        db: &DatabaseConnection,
        refresh_token: &str,
        user_id: Uuid,
    ) -> Result<()> {
        let session = Session::find()
            .filter(session::Column::RefreshToken.eq(refresh_token))
            .filter(session::Column::UserId.eq(user_id))
            .filter(session::Column::IsActive.eq(true))
            .one(db)
            .await?;

        if let Some(session) = session {
            Self::revoke_token(db, &session.access_token_jti, user_id, Some("logout".to_string())).await?;

            let mut session: session::ActiveModel = session.into();
            session.is_active = Set(false);
            session.update(db).await?;
        }

        Ok(())
    }
}
