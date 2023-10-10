
use argon2::PasswordHasher;
use models::users::{Entity as User, self};
use sea_orm::{
    DbErr,
    Condition,
    EntityTrait,
    QueryFilter,
    ColumnTrait,
    ActiveModelTrait,
    DatabaseConnection, prelude::{Uuid, DateTimeWithTimeZone},
};

pub struct Query;

pub struct Mutation;

pub struct UserUpdate {
    pub name: Option<String>,
    pub phone: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub session_data: Option<String>,
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
}

impl Mutation {
    pub async fn create_user(db: &DatabaseConnection, name: &str, phone: Option<String>, email: Option<String>, password: Option<String>) -> Result<Uuid, DbErr> {
        let mut user = users::ActiveModel {
            id: sea_orm::ActiveValue::Set(Uuid::new_v4()),
            name: sea_orm::ActiveValue::Set(String::from(name)),
            phone: sea_orm::ActiveValue::Set(phone),
            email: sea_orm::ActiveValue::Set(email),
            session_data: sea_orm::ActiveValue::Set(nanoid::nanoid!(64)),
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

        if updates.name.is_some() {
            user.name = sea_orm::ActiveValue::Set(updates.name.unwrap());
        }

        if updates.session_data.is_some() {
            user.session_data = sea_orm::ActiveValue::Set(updates.session_data.unwrap());
        }

        if updates.email_verified_at.is_some() {
            user.email_verified_at = sea_orm::ActiveValue::Set(updates.email_verified_at);
        }

        if updates.phone_verified_at.is_some() {
            user.phone_verified_at = sea_orm::ActiveValue::Set(updates.phone_verified_at);
        }

        if updates.email.is_some() {
            user.email = sea_orm::ActiveValue::Set(updates.email);
            user.email_verified_at = sea_orm::ActiveValue::Set(None);
        }

        if updates.phone.is_some() {
            user.phone = sea_orm::ActiveValue::Set(updates.phone);
            user.phone_verified_at = sea_orm::ActiveValue::Set(None);
        }

        if updates.password.is_some() {
            let salt = argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);

            user.password = sea_orm::ActiveValue::Set(Some(
                argon2::Argon2::default()
                    .hash_password(updates.password.unwrap().as_bytes(), &salt)
                    .expect("fail to hash password")
                    .to_string()
            ));
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
}
