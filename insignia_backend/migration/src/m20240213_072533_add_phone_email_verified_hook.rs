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
            "create or replace function send_integration_event_on_passkey_updated()
            returns trigger as
            $$
            begin
                if TG_OP = 'INSERT' then
                    perform send_integration_callback_event(
                        'UserPasskeyAdded',
                        json_build_object(
                            'user_id', new.user_id,
                            'passkey_id', new.id,
                            'passkey_name', new.name
                        )
                    );
                elsif TG_OP = 'DELETE' then
                    perform send_integration_callback_event(
                        'UserPasskeyRemoved',
                        json_build_object(
                            'user_id', old.user_id,
                            'passkey_id', old.id,
                            'passkey_name', old.name
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
            "
        )
        .await?;

        db.execute_unprepared(
            "create or replace trigger send_integration_event_on_email_verified
            after update on users
            for each row
            when (old.email_verified_at is distinct from new.email_verified_at and new.email_verified_at is not null)
            execute function send_integration_event_on_phone_email_verified()
            ",
        )
        .await?;

        db.execute_unprepared(
            "create or replace trigger send_integration_event_on_passkey_updated
            after insert or delete on users_webauthn_credentials
            for each row
            execute function send_integration_event_on_passkey_updated()
            ",
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        db.execute_unprepared(
            "drop trigger if exists send_integration_event_on_phone_verified on users",
        )
        .await?;

        db.execute_unprepared(
            "drop trigger if exists send_integration_event_on_email_verified on users",
        )
        .await?;

        db.execute_unprepared(
            "drop trigger if exists send_integration_event_on_passkey_updated on users_webauthn_credentials",
        )
        .await?;

        db.execute_unprepared(
            "drop function if exists send_integration_event_on_phone_email_verified()",
        )
        .await?;

        db.execute_unprepared(
            "drop function if exists send_integration_event_on_passkey_updated()",
        )
        .await?;

        Ok(())
    }
}
