use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        db.execute_unprepared("create extension if not exists pg_cron")
            .await?;

        db.execute_unprepared("
        select cron.schedule(
            'remove-unsuccessful-register-user',
            '*/8 * * * *',
            $$
            delete from users
            where password is null
            and (created_at + interval '8 minutes') < now()
            and phone_verified_at is null
            and email_verified_at is null
            and id not in (select user_id from users_webauthn_credentials)
            $$
        )
        ")
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        db.execute_unprepared("drop extension if exists pg_cron")
            .await?;

        Ok(())
    }
}
