
use std::fmt;

use sea_orm::DbErr;
use redis::RedisError;
use actix::MailboxError;
use actix_web::{ResponseError, http::StatusCode, HttpResponse};

#[derive(Debug)]
pub enum AppErrorCode {
    Argon2UnknownError,
    DragonflyUnknownError,
    JsonWebTokenUnknownError,
}

impl AppErrorCode {
    fn to_string(&self) -> String {
        match &*self {
            _ =>
                "isgn@99".to_string()
        }
    }
}

#[derive(Debug)]
pub struct AppError {
    pub code: Option<AppErrorCode>,
    pub message: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct AppHttpErrorResponseDto {
    pub code: String,
    pub message: String,
}

impl fmt::Display for AppHttpErrorResponseDto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<argon2::password_hash::Error> for AppError {
    fn from(value: argon2::password_hash::Error) -> Self {
        match value {
            _ =>
                Self {
                    code: Some(AppErrorCode::Argon2UnknownError),
                    message: Some(value.to_string()),
                }
        }
    }
}

impl From<RedisError> for AppError {
    fn from(value: RedisError) -> Self {
        match value {
            _ => Self {
                code: Some(AppErrorCode::DragonflyUnknownError),
                message: Some(value.to_string()),
            }
        }
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(value: jsonwebtoken::errors::Error) -> Self {
        match value {
            _ => Self {
                code: Some(AppErrorCode::JsonWebTokenUnknownError),
                message: Some(value.to_string()),
            }
        }
    }
}

impl AppError {
    fn message(&self) -> String {
        match self {
            _ => "invalid request".to_string()
        }
    }
}

impl From<serde_json::Error> for AppHttpErrorResponseDto {
    fn from(value: serde_json::Error) -> Self {
        match value {
            val => Self {
                code: "insig@99".to_string(),
                message: val.to_string(),
            }
        }
    }
}

impl From<sea_orm::TransactionError<DbErr>> for AppHttpErrorResponseDto {
    fn from(value: sea_orm::TransactionError<DbErr>) -> Self {
        match value {
            _ => Self {
                code: "insig@99".to_string(),
                message: "unexpected error".to_string(),
            }
        }
    }
}

impl From<sea_orm::DbErr> for AppHttpErrorResponseDto {
    fn from(value: sea_orm::DbErr) -> Self {
        match &value {
            _ => Self {
                code: "insig@99".to_string(),
                message: "unexpected error".to_string()
            }
        }
    }
}

impl From<MailboxError> for AppHttpErrorResponseDto {
    fn from(value: MailboxError) -> Self {
        match value {
            _ => Self {
                code: "insig@99".to_string(),
                message: "unexpected error".to_string(),
            }
        }
    }
}

impl From<AppError> for AppHttpErrorResponseDto {
    fn from(value: AppError) -> Self {
        match &value {
            AppError {
                code: Some(code),
                message: _,
            } => Self {
                code: code.to_string(),
                message: value.message(),
            },
            _ => Self {
                code: "insig@99".to_string(),
                message: "unexpected error".to_string(),
            }
        }
    }
}

impl ResponseError for AppHttpErrorResponseDto {
    fn status_code(&self) -> StatusCode {
        match self.code {
            _ =>
                StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .json(self)
    }
}
