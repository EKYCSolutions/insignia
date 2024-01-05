use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        db.execute_unprepared(
            "create extension if not exists http"
        )
            .await?;

        db.execute_unprepared(
            "create or replace function send_integration_callback_event(event text, data json)
            returns void as
            $$
            declare
                setting settings;
                callback_resp record;
            begin
                select * into setting
                from settings
                order by id desc
                limit 1;

                if setting is not null and setting.webhook_receiver_url is not null and setting.webhook_receiver_api_key is not null then
                    select * into callback_resp
                    from http((
                        'POST',
                        setting.webhook_receiver_url,
                        array[http_header('x-api-key', setting.webhook_receiver_api_key)],
                        'application/json',
                        json_build_object(
                            'event', event,
                            'created_at', to_char(now()::timestamp at time zone 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                            'data', data
                        )
                    )::http_request);

                    if callback_resp.status = 204 or callback_resp.status = 200 then
                        return;
                    end if;

                    raise 'fail to send % integration event - %, %', event, callback_resp.status, callback_resp.content;
                end if;
            end;
            $$ language plpgsql
            "
        )
            .await?;

        db.execute_unprepared(
            "create or replace function send_integration_event_on_user_created_or_deleted()
            returns trigger as
            $$
            begin
                if old is null then
                    perform send_integration_callback_event(
                        'UserCreated',
                        json_build_object(
                            'user_id', new.id,
                            'username', new.name,
                            'created_at', new.created_at,
                            'extras', new.extras_meta
                        )
                    );

                    return new;
                end if;

                perform send_integration_callback_event(
                    'UserDeleted',
                    json_build_object(
                        'user_id', new.id
                    )
                );

                return old;
            end;
            $$ language plpgsql
            "
        )
            .await?;

        db.execute_unprepared(
            "create or replace trigger send_integration_event_on_user_created_or_deleted
            after insert or delete on users
            for each row
            execute function send_integration_event_on_user_created_or_deleted()
            "
        )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        db.execute_unprepared(
            "drop trigger if exists send_integration_event_on_user_created_or_deleted on users"
        )
            .await?;

        db.execute_unprepared(
            "drop function if exists send_integration_event_on_user_created_or_deleted(text, json)"
        )
            .await?;

        db.execute_unprepared(
            "drop function if exists send_integration_callback_event(text, json)"
        )
            .await?;

        db.execute_unprepared(
            "drop extension if exists http"
        )
            .await?;

        Ok(())
    }
}
