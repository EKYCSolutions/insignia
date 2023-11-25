use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(DelegableUserPermission::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(DelegableUserPermission::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(DelegableUserPermission::Name).string().not_null())
                    .col(ColumnDef::new(DelegableUserPermission::Label).string().null())
                    .col(ColumnDef::new(DelegableUserPermission::ZanzibarValue).string().null())
                    .col(ColumnDef::new(DelegableUserPermission::CreatedAt).timestamp_with_time_zone().default(Expr::current_timestamp()).not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(DelegableUserPermission::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
#[iden(rename = "delegable_user_permissions")]
pub enum DelegableUserPermission {
    Table,
    Id,
    Name,
    Label,
    ZanzibarValue,
    CreatedAt,
}
