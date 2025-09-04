use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE TABLE IF NOT EXISTS user_session (
                    id UUID PRIMARY KEY,
                    user_id UUID NOT NULL,
                    refresh_token VARCHAR NOT NULL UNIQUE,
                    access_token_jti VARCHAR NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL,
                    last_used_at TIMESTAMPTZ NOT NULL,
                    ip_address VARCHAR NULL,
                    user_agent VARCHAR NULL,
                    is_active BOOLEAN NOT NULL DEFAULT true,
                    CONSTRAINT fk_user_session_user 
                        FOREIGN KEY (user_id) 
                        REFERENCES "user"(id) 
                        ON DELETE CASCADE
                );
                
                CREATE INDEX IF NOT EXISTS idx_user_session_user_id ON user_session(user_id);
                CREATE INDEX IF NOT EXISTS idx_user_session_refresh_token ON user_session(refresh_token);
                CREATE INDEX IF NOT EXISTS idx_user_session_expires_at ON user_session(expires_at);
                "#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS user_session CASCADE;")
            .await?;

        Ok(())
    }
}