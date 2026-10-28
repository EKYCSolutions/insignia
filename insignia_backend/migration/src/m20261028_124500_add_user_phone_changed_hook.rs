use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        db.execute_unprepared(
            "create or replace function send_integration_event_on_phone_email_verified()
            returns trigger as
            $$
            begin
                if old.phone is distinct from new.phone and old.phone is not null then
                    perform send_integration_callback_event(
                        'UserPhoneChanged',
                        json_build_object(
                            'user_id', new.id,
                            'old_phone', old.phone,
                            'new_phone', new.phone,
                            'phone', new.phone,
                            'phone_verified_at', new.phone_verified_at
                        )
                    );
                elsif old.phone_verified_at is null and new.phone_verified_at is not null then
                    perform send_integration_callback_event(
                        'UserPhoneVerified',
                        json_build_object(
                            'user_id', new.id,
                            'phone', new.phone,
                            'phone_verified_at', new.phone_verified_at
                        )
                    );
                elsif old.email_verified_at is distinct from new.email_verified_at then
                    perform send_integration_callback_event(
                        'UserEmailVerified',
                        json_build_object(
                            'user_id', new.id,
                            'email', new.email,
                            'email_verified_at', new.email_verified_at
                        )
                    );
                end if;

                return new;
            end;
            $$ language plpgsql
            ",
        )
        .await?;

        db.execute_unprepared(
            "create or replace trigger send_integration_event_on_phone_verified
            after update on users
            for each row
            when (
                (old.phone_verified_at is null and new.phone_verified_at is not null)
                or (old.phone is distinct from new.phone and new.phone is not null)
            )
            execute function send_integration_event_on_phone_email_verified()
            ",
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        db.execute_unprepared(
            "create or replace function send_integration_event_on_phone_email_verified()
            returns trigger as
            $$
            begin
                if old.phone_verified_at is distinct from new.phone_verified_at then
                    perform send_integration_callback_event(
                        'UserPhoneVerified',
                        json_build_object(
                            'user_id', new.id,
                            'phone', new.phone,
                            'phone_verified_at', new.phone_verified_at
                        )
                    );
                elsif old.email_verified_at is distinct from new.email_verified_at then
                    perform send_integration_callback_event(
                        'UserEmailVerified',
                        json_build_object(
                            'user_id', new.id,
                            'email', new.email,
                            'email_verified_at', new.email_verified_at
                        )
                    );
                end if;

                return new;
            end;
            $$ language plpgsql
            ",
        )
        .await?;

        db.execute_unprepared(
            "create or replace trigger send_integration_event_on_phone_verified
            after update on users
            for each row
            when (old.phone_verified_at is distinct from new.phone_verified_at and new.phone_verified_at is not null)
            execute function send_integration_event_on_phone_email_verified()
            ",
        )
        .await?;

        Ok(())
    }
}
