
use argon2::PasswordHasher;
use models::{
    oauth_clients,
    users::{Entity as User, self},
    users_oauth_consents::{Entity as UserOauthConsent, self},
    users_oauth_authorized_clients::{Entity as UserOauthAuthorizedClient, self},
};
use sea_orm::{
    prelude::{DateTimeWithTimeZone, Uuid}, ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, DbErr, EntityTrait, QueryFilter, QuerySelect, TransactionError, TransactionTrait
};

pub struct Query;

pub struct Mutation;

pub struct UserUpdate {
    pub name: Option<String>,
    pub phone: Option<Option<String>>,
    pub email: Option<Option<String>>,
    pub password: Option<Option<String>>,
    pub session_data: Option<String>,
    pub email_verified_at: Option<DateTimeWithTimeZone>,
    pub phone_verified_at: Option<DateTimeWithTimeZone>,
}

pub struct AdminCreateUserInput {
    pub name: String,
    pub phone: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub extras_meta: Option<serde_json::Value>,
    pub email_verified_at: Option<DateTimeWithTimeZone>,
    pub phone_verified_at: Option<DateTimeWithTimeZone>,
}

impl Query {
    pub async fn get_existence(db: &DatabaseConnection, identifier: &str) -> Result<Option<users::Model>, DbErr> {
        User::find()
        .filter(
            Condition::any()
            .add(users::Column::Name.eq(identifier))
            .add(users::Column::Email.eq(identifier))
            .add(users::Column::Phone.eq(identifier))
        )
        .one(db)
        .await
    }

    pub async fn list_users(
        db: &DatabaseConnection,
        limit: u64,
        offset: u64
    ) -> Result<Vec<(models::users::Model, Vec<models::users_webauthn_credentials::Model>)>, DbErr> {
        User::find()
            .find_with_related(models::users_webauthn_credentials::Entity)
            .limit(Some(limit))
            .offset(Some(offset))
            .all(db)
            .await
    }

    pub async fn get_user_info(db: &DatabaseConnection, identifier: &str) -> Result<Vec<(models::users::Model, Vec<models::users_webauthn_credentials::Model>)>, DbErr> {
        User::find()
        .find_with_related(models::users_webauthn_credentials::Entity)
        .filter(
            Condition::any()
            .add(users::Column::Name.eq(identifier))
            .add(users::Column::Email.eq(identifier))
            .add(users::Column::Phone.eq(identifier))
        )
        .all(db)
        .await
    }

    pub async fn get_user_info_by_id(db: &DatabaseConnection, id: Uuid) -> Result<Vec<(models::users::Model, Vec<models::users_webauthn_credentials::Model>)>, DbErr> {
        User::find()
        .find_with_related(models::users_webauthn_credentials::Entity)
        .filter(users::Column::Id.eq(id))
        .all(db)
        .await
    }

    pub async fn list_oauth_authorized_client(
        db: &DatabaseConnection,
        user: users::Model
    ) -> Result<Vec<users_oauth_authorized_clients::Model>, DbErr> {
        Ok(
            UserOauthAuthorizedClient::find()
                .filter(users_oauth_authorized_clients::Column::UserId.eq(user.id))
                .all(db)
                .await?
        )
    }

    pub async fn list_oauth_consents(
        db: &DatabaseConnection,
        client: models::users_oauth_authorized_clients::Model,
    ) -> Result<Vec<users_oauth_consents::Model>, DbErr> {
        Ok(
            UserOauthConsent::find()
                .filter(users_oauth_consents::Column::UserOauthAuthorizedClientId.eq(client.id))
                .all(db)
                .await?
        )
    }

    pub async fn get_oauth_authorized_client_by_client_id(
        db: &DatabaseConnection,
        id: i32,
        user_id: Uuid
    ) -> Result<Option<users_oauth_authorized_clients::Model>, DbErr> {
        Ok(
            UserOauthAuthorizedClient::find()
                .filter(users_oauth_authorized_clients::Column::UserId.eq(user_id))
                .filter(users_oauth_authorized_clients::Column::OauthClientId.eq(id))
                .one(db)
                .await?
        )
    }
}

impl Mutation {
    pub async fn admin_create_user(
        db: &DatabaseConnection,
        user_create_input: AdminCreateUserInput,
    ) -> Result<users::Model, DbErr> {
        let mut user_active_model = users::ActiveModel {
            id: sea_orm::ActiveValue::Set(Uuid::new_v4()),
            name: sea_orm::ActiveValue::Set(user_create_input.name),
            phone: sea_orm::ActiveValue::Set(user_create_input.phone),
            email: sea_orm::ActiveValue::Set(user_create_input.email),
            session_data: sea_orm::ActiveValue::Set(nanoid::nanoid!(64)),
            extras_meta: sea_orm::ActiveValue::Set(user_create_input.extras_meta),
            ..Default::default()
        };

        match &user_active_model.password {
            sea_orm::ActiveValue::Set(Some(password)) => {
                let salt = argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);

                user_active_model.password = sea_orm::ActiveValue::Set(
                    Some(argon2::Argon2::default()
                        .hash_password(password.as_bytes(), &salt)
                        .expect("fail to hash password").to_string())
                );
            },

            _ => (),
        };

        let user = user_active_model.insert(db)
            .await?;

        Ok(user)
    }

    pub async fn create_user(db: &DatabaseConnection, name: &str, phone: Option<String>, email: Option<String>, password: Option<String>, extras_meta: Option<serde_json::Value>) -> Result<Uuid, DbErr> {
        let mut user = users::ActiveModel {
            id: sea_orm::ActiveValue::Set(Uuid::new_v4()),
            name: sea_orm::ActiveValue::Set(String::from(name)),
            phone: sea_orm::ActiveValue::Set(phone),
            email: sea_orm::ActiveValue::Set(email),
            session_data: sea_orm::ActiveValue::Set(nanoid::nanoid!(64)),
            extras_meta: sea_orm::ActiveValue::Set(extras_meta),
            ..Default::default()
        };

        if let Some(password) = password {
            let salt = argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);

            user.password = sea_orm::ActiveValue::Set(
                Some(argon2::Argon2::default().hash_password(password.as_bytes(), &salt).expect("fail to hash password").to_string())
            );
        }

        let user = user.insert(db).await?;

        Ok(user.id)
    }

    pub async fn update_user(db: &DatabaseConnection, user: models::users::Model, updates: UserUpdate) -> Result<(), DbErr> {
        let mut user: models::users::ActiveModel = user.into();

        if let Some(name) = updates.name {
            user.name = sea_orm::ActiveValue::Set(name);
        }

        if let Some(session_data) = updates.session_data {
            user.session_data = sea_orm::ActiveValue::Set(session_data);
        }

        if updates.email_verified_at.is_some() {
            user.email_verified_at = sea_orm::ActiveValue::Set(updates.email_verified_at);
        }

        if updates.phone_verified_at.is_some() {
            user.phone_verified_at = sea_orm::ActiveValue::Set(updates.phone_verified_at);
        }

        if let Some(email) = updates.email {
            user.email = sea_orm::ActiveValue::Set(email);
            user.email_verified_at = sea_orm::ActiveValue::Set(None);
        }

        if let Some(phone) = updates.phone {
            user.phone = sea_orm::ActiveValue::Set(phone);
            user.phone_verified_at = sea_orm::ActiveValue::Set(None);
        }

        if let Some(password) = updates.password {
            if let Some(password) = password {
                let salt = argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);

                user.password = sea_orm::ActiveValue::Set(Some(
                    argon2::Argon2::default()
                        .hash_password(password.as_bytes(), &salt)
                        .expect("fail to hash password")
                        .to_string()
                ));
            } else {
                user.password = sea_orm::ActiveValue::Set(None);
            }
        }

        user.update(db).await?;

        Ok(())
    }

    pub async fn set_recovery_data(db: &DatabaseConnection, user: models::users::Model, salt: &str, part: &str) -> Result<(), DbErr> {
        let mut user: models::users::ActiveModel = user.into();

        let h_salt = argon2::password_hash::SaltString::generate(
            &mut argon2::password_hash::rand_core::OsRng
        );

        let part = argon2::Argon2::default().hash_password(
            part.as_bytes(),
            &h_salt
        )
        .expect("fail to hash the recovery data hash part")
        .to_string();

        user.recovery_data = sea_orm::ActiveValue::Set(Some(format!("{salt}.{part}")));

        user.update(db).await?;

        Ok(())
    }

    pub async fn remove_user(db: &DatabaseConnection, user_id: Uuid) -> Result<(), DbErr> {
        users::Entity::delete_by_id(user_id)
            .exec(db)
            .await?;

        Ok(())
    }

    pub async fn oauth_consent_for_app_to_act_on_behalf_of_user(
        db: &DatabaseConnection,
        user: models::users::Model,
        oauth_client: oauth_clients::Model,
        consents_object: Vec<models::oauth::UserOauthConsentObjectRequestDto>
    ) -> Result<(users_oauth_authorized_clients::Model, Vec<users_oauth_consents::Model>), TransactionError<DbErr>> {
        let result = db.transaction::<_, (users_oauth_authorized_clients::Model, Vec<users_oauth_consents::Model>), DbErr>(|txn| {
            Box::pin(async move {
                let mut consents_actions = vec![];

                let authorized_client = users_oauth_authorized_clients::ActiveModel {
                    token_key: sea_orm::ActiveValue::Set(nanoid::nanoid!(32)),
                    user_id: sea_orm::ActiveValue::Set(user.id),
                    oauth_client_id: sea_orm::ActiveValue::Set(oauth_client.id),
                    ..Default::default()
                }
                    .insert(txn)
                    .await?;

                for cons_obj in consents_object {
                    let consent = users_oauth_consents::ActiveModel {
                        oauth_scope_id: sea_orm::ActiveValue::Set(cons_obj.oauth_scope_id),
                        zanzibar_subject: sea_orm::ActiveValue::Set(cons_obj.zanzibar_subject),
                        zanzibar_relative: sea_orm::ActiveValue::Set(cons_obj.zanzibar_relative),
                        user_oauth_authorized_client_id: sea_orm::ActiveValue::Set(authorized_client.id),
                        ..Default::default()
                    };

                    consents_actions.push(consent.insert(txn));
                }

                let consents_actions = futures::future::join_all(consents_actions)
                    .await
                    .iter()
                    .map(|result| {
                        result
                            .as_ref()
                            .unwrap()
                            .to_owned()
                    })
                    .collect::<Vec<users_oauth_consents::Model>>();

                Ok((authorized_client, consents_actions))
            })
        })
            .await?;

        Ok(result)
    }
}
