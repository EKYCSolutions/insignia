
use std::fmt;

use actix_web::{ResponseError, http::StatusCode, HttpResponse};

#[derive(Debug)]
pub enum AppErrorCode {
    Argon2UnknownError,
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
pub struct AppHttpError {
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

impl From<argon2::password_hash::Error> for AppHttpError {
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

impl AppHttpError {
    fn message(&self) -> String {
        match self {
            _ => "invalid request".to_string()
        }
    }
}

impl From<AppHttpError> for AppHttpErrorResponseDto {
    fn from(value: AppHttpError) -> Self {
        match &value {
            AppHttpError {
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
