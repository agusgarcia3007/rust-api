use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20231201_000001_create_users_table::Migration),
            Box::new(m20241201_000001_create_token_blacklist::Migration),
            Box::new(m20241201_000002_create_user_session::Migration),
        ]
    }
}

mod m20241201_000001_create_token_blacklist;
mod m20241201_000002_create_user_session;

mod m20231201_000001_create_users_table {
    use super::*;

    #[derive(DeriveMigrationName)]
    pub struct Migration;

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .create_table(
                    Table::create()
                        .table(User::Table)
                        .if_not_exists()
                        .col(ColumnDef::new(User::Id).uuid().not_null().primary_key())
                        .col(ColumnDef::new(User::Email).string().not_null().unique_key())
                        .col(ColumnDef::new(User::PasswordHash).string().not_null())
                        .col(ColumnDef::new(User::Name).string().not_null())
                        .col(ColumnDef::new(User::CreatedAt).timestamp_with_time_zone().not_null())
                        .col(ColumnDef::new(User::UpdatedAt).timestamp_with_time_zone().not_null())
                        .to_owned(),
                )
                .await
        }

        async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .drop_table(Table::drop().table(User::Table).to_owned())
                .await
        }
    }

    #[derive(DeriveIden)]
    enum User {
        Table,
        Id,
        Email,
        PasswordHash,
        Name,
        CreatedAt,
        UpdatedAt,
    }
}
