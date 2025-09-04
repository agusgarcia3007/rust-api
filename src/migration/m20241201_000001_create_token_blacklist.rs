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
                CREATE TABLE IF NOT EXISTS token_blacklist (
                    id UUID PRIMARY KEY,
                    token_jti VARCHAR NOT NULL,
                    user_id UUID NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    revoked_at TIMESTAMPTZ NOT NULL,
                    reason VARCHAR NULL,
                    CONSTRAINT fk_token_blacklist_user 
                        FOREIGN KEY (user_id) 
                        REFERENCES "user"(id) 
                        ON DELETE CASCADE
                );
                
                CREATE INDEX IF NOT EXISTS idx_token_blacklist_jti ON token_blacklist(token_jti);
                CREATE INDEX IF NOT EXISTS idx_token_blacklist_expires_at ON token_blacklist(expires_at);
                "#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS token_blacklist CASCADE;")
            .await?;

        Ok(())
    }
}