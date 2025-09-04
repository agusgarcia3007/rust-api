use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .add_column(
                        ColumnDef::new(User::EmailVerified)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .add_column(
                        ColumnDef::new(User::EmailVerificationToken)
                            .string()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(User::EmailVerificationExpiresAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(User::PasswordResetToken)
                            .string()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(User::PasswordResetExpiresAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .drop_column(User::EmailVerified)
                    .drop_column(User::EmailVerificationToken)
                    .drop_column(User::EmailVerificationExpiresAt)
                    .drop_column(User::PasswordResetToken)
                    .drop_column(User::PasswordResetExpiresAt)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum User {
    Table,
    EmailVerified,
    EmailVerificationToken,
    EmailVerificationExpiresAt,
    PasswordResetToken,
    PasswordResetExpiresAt,
}