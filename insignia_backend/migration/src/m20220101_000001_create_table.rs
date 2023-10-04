use sea_orm_migration::prelude::*;

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
                    .col(
                        ColumnDef::new(User::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(User::Name).string().not_null())
                    .col(ColumnDef::new(User::SessionData).string().not_null())
                    .col(ColumnDef::new(User::RecoveryData).string().null())
                    .col(ColumnDef::new(User::CreatedAt).timestamp_with_time_zone().default(Expr::current_timestamp()).not_null())
                    .to_owned(),
            )
            .await?;

        manager.create_index(
            sea_query::Index::create()
            .table(User::Table)
            .col(User::Name)
            .unique()
            .to_owned()
        ).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(User::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
#[iden(rename = "users")]
pub enum User {
    Table,
    Id,
    Name,
    SessionData,
    RecoveryData,
    CreatedAt,
}
