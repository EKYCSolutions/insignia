
use argon2::PasswordHasher;
use models::users::{Entity as User, self};
use sea_orm::{
    DbErr,
    Condition,
    EntityTrait,
    QueryFilter,
    ColumnTrait,
    ActiveModelTrait,
    DatabaseConnection, prelude::Uuid,
};

pub struct Query;

pub struct Mutation;

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

        let salt = argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);

        if let Some(password) = password {
            user.password = sea_orm::ActiveValue::Set(
                Some(argon2::Argon2::default().hash_password(password.as_bytes(), &salt).expect("fail to hash password").to_string())
            );
        }

        let user = user.insert(db).await?;

        Ok(user.id)
    }
}
