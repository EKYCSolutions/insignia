
use sea_orm::{DbErr, DatabaseConnection, EntityTrait, ActiveValue, ActiveModelTrait, QueryFilter, ColumnTrait, IntoActiveModel};

use models::{
    oauth_scopes::{Entity as OauthScope, self},
    oauth_clients::{Entity as OauthClient, self},
    delegable_user_permissions::{Entity as DelegableUserPermission, self}, oauth::OauthClientMutationDto,
};

pub struct Query;

pub struct Mutation;

impl Query {
    pub async fn list_oauth_scopes(db_conn: &DatabaseConnection) -> Result<Vec<oauth_scopes::Model>, DbErr> {
        Ok(
            OauthScope::find()
                .all(db_conn)
                .await?
        )
    }

    pub async fn list_delegable_user_permission(db_conn: &DatabaseConnection) -> Result<Vec<delegable_user_permissions::Model>, DbErr> {
        Ok(
            DelegableUserPermission::find()
                .all(db_conn)
                .await?
        )
    }

    pub async fn list_oauth_client(db_conn: &DatabaseConnection) -> Result<Vec<oauth_clients::Model>, DbErr> {
        Ok(
            OauthClient::find()
                .all(db_conn)
                .await?
        )
    }

    pub async fn get_oauth_client_by_client_id(db_conn: &DatabaseConnection, client_id: String) -> Result<Option<oauth_clients::Model>, DbErr> {
        Ok(
            OauthClient::find()
                .filter(oauth_clients::Column::ClientId.eq(client_id))
                .one(db_conn)
                .await?
        )
    }
}

impl Mutation {
    pub async fn add_delegable_user_permission(
        db_conn: &DatabaseConnection,
        name: String,
        label: Option<String>,
        zanzibar_value: Option<String>
    ) -> Result<delegable_user_permissions::Model, DbErr> {
        let delegable_user_permission = delegable_user_permissions::ActiveModel {
            name: ActiveValue::Set(name),
            label: ActiveValue::Set(label),
            zanzibar_value: ActiveValue::Set(zanzibar_value),
            ..Default::default()
        };

        Ok(
            delegable_user_permission
                .insert(db_conn)
                .await?
        )
    }

    pub async fn remove_delegable_user_permission(db_conn: &DatabaseConnection, id: i32) -> Result<(), DbErr> {
        let delegable_user_permission = DelegableUserPermission::find()
            .filter(delegable_user_permissions::Column::Id.eq(id))
            .one(db_conn)
            .await?;

        if let Some(val) = delegable_user_permission {
            let val = val.into_active_model();

            val
                .delete(db_conn)
                .await?;
        }

        Ok(())
    }

    pub async fn add_oauth_scope(
        db_conn: &DatabaseConnection,
        name: String,
        label: Option<String>,
        delegable_user_permission_id: i32
    ) -> Result<oauth_scopes::Model, DbErr> {
        let oauth_scope = oauth_scopes::ActiveModel {
            name: ActiveValue::Set(name),
            label: ActiveValue::Set(label),
            delegable_user_permission_id: ActiveValue::Set(delegable_user_permission_id),
            ..Default::default()
        };

        Ok(
            oauth_scope
                .insert(db_conn)
                .await?
        )
    }

    pub async fn remove_oauth_scope(db_conn: &DatabaseConnection, id: i32) -> Result<(), DbErr> {
        let oauth_scope = OauthScope::find()
            .filter(oauth_scopes::Column::Id.eq(id))
            .one(db_conn)
            .await?;

        if let Some(val) = oauth_scope {
            let val = val.into_active_model();

            val
                .delete(db_conn)
                .await?;
        }

        Ok(())
    }

    pub async fn add_oauth_client(
        db_conn: &DatabaseConnection,
        args: &OauthClientMutationDto,
    ) -> Result<oauth_clients::Model, DbErr> {
        let oauth_client = oauth_clients::ActiveModel {
            name: ActiveValue::Set(args.name.to_owned()),
            label: ActiveValue::Set(args.label.to_owned()),
            client_id: ActiveValue::Set(nanoid::nanoid!(32)),
            client_type: ActiveValue::Set(args.client_type.to_string()),
            audiences: ActiveValue::Set(args.audiences.to_owned()),
            redirect_uris: ActiveValue::Set(args.redirect_uris.to_owned()),
            authn_flow: ActiveValue::Set(
                match args.client_type {
                    models::oauth::OauthClientType::Public => Some(args.authn_flow.to_string()),
                    models::oauth::OauthClientType::Confidential => None,
                }
            ),
            client_secret: ActiveValue::Set(
                match args.authn_flow {
                    models::oauth::OauthFlow::PKCE => None,
                    models::oauth::OauthFlow::ClientCredential => Some(nanoid::nanoid!(64)),
                }
            ),
            ..Default::default()
        };

        let oauth_client = oauth_client
            .insert(db_conn)
            .await?;

        Ok(oauth_client)
    }

    pub async fn remove_oauth_client(
        db_conn: &DatabaseConnection,
        id: i32,
    ) -> Result<(), DbErr> {
        let oauth_client = OauthClient::find()
            .filter(oauth_clients::Column::Id.eq(id))
            .one(db_conn)
            .await?;

        if let Some(val) = oauth_client {
            let val = val.into_active_model();

            val
                .delete(db_conn)
                .await?;
        }

        Ok(())
    }
}
