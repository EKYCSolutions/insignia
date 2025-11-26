use std::collections::HashMap;
use std::{pin::Pin, str::FromStr};

use nanoid::nanoid;
use awc::http::StatusCode;
use actix::{Actor, Context, Message, Handler, ResponseFuture, Addr, MailboxError};

use models::http_error::AppError;
use crate::dragonfly::DragonflyService;

#[derive(Debug)]
pub enum SMSOtpError {
    FailToSendCode(String),
    FailToVerifyCode(String),
    InvalidRequest(String),
    UnknownError(String),
}

impl From<awc::error::PayloadError> for SMSOtpError {
    fn from(value: awc::error::PayloadError) -> Self {
        match value {
            err =>
                Self::UnknownError(err.to_string())
        }
    }
}

impl From<awc::error::SendRequestError> for SMSOtpError {
    fn from(value: awc::error::SendRequestError) -> Self {
        match value {
            err =>
                Self::UnknownError(err.to_string())
        }
    }
}

impl From<awc::error::JsonPayloadError> for SMSOtpError {
    fn from(value: awc::error::JsonPayloadError) -> Self {
        match value {
            err =>
                Self::UnknownError(err.to_string())
        }
    }
}

impl From<MailboxError> for SMSOtpError {
    fn from(value: MailboxError) -> Self {
        match value {
            err =>
                Self::UnknownError(err.to_string())
        }
    }
}

impl From<AppError> for SMSOtpError {
    fn from(value: AppError) -> Self {
        match value {
            err => Self::UnknownError(err.to_string()),
        }
    }
}

#[derive(Debug)]
pub enum SMSOtpResult {
    SendResult(bool),
    VerifyResult(bool),
}

trait SMSOtp {
    fn send(&self, to: &str) -> Pin<Box<dyn futures::Future<Output = Result<SMSOtpResult, SMSOtpError>> + '_>>;

    fn verify(&self, to: &str, code: &str) -> Pin<Box<dyn futures::Future<Output = Result<SMSOtpResult, SMSOtpError>> + '_>>;
}

#[derive(Clone)]
pub struct TwilioServiceConfig {
    base_url: String,
    verify_sid: String,
}

#[derive(Clone)]
pub struct InfobipServiceConfig {
    base_url: String,
    twofa_app_id: String,
    twofa_message_template_id: String,
    cache: Addr<DragonflyService>,
}

#[derive(Clone)]
pub struct PlasgateServiceConfig {
    base_url: String,
    private_key: String,
    sender_name: String,
    cache: Addr<DragonflyService>,
}

#[derive(Clone, Debug)]
pub struct GenericServiceConfig {
    url: String,
    http_method: String,
    http_body_template: String,
    cache: Addr<DragonflyService>,
}

pub trait CacheService {
    fn get_cache(&self) -> &Addr<DragonflyService>;
}

#[derive(Clone)]
pub enum CoreSMSOtp {
    Generic(awc::Client, GenericServiceConfig),
    Twilio(awc::Client, TwilioServiceConfig),
    Infobip(awc::Client, InfobipServiceConfig),
    Plasgate(awc::Client, PlasgateServiceConfig),
    Mock(),
}

impl CacheService for CoreSMSOtp {
    fn get_cache(&self) -> &Addr<DragonflyService> {
        match self {
            CoreSMSOtp::Generic(_client, conf) => {
                &conf.cache
            }
            CoreSMSOtp::Plasgate(_client, conf) => {
                &conf.cache
            }

            CoreSMSOtp::Twilio(_client, _conf) => todo!(),
            CoreSMSOtp::Infobip(_client, _conf) => todo!(),
            CoreSMSOtp::Mock() => todo!(),
        }
    }
}

impl CoreSMSOtp {
    pub fn new_mock() -> Self {
        Self::Mock()
    }

    pub fn new_plasgate(plasgate_sender_name: &str, plasgate_secret: &str, plasgate_private_key: &str, cache_actor_addr: Addr<DragonflyService>) -> Self {
        let client = awc::ClientBuilder::new()
            .add_default_header(("x-secret", plasgate_secret))
            .finish();

        Self::Plasgate(
            client,
            PlasgateServiceConfig {
                base_url: "https://cloudapi.plasgate.com".to_string(),
                private_key: plasgate_private_key.to_string(),
                sender_name: plasgate_sender_name.to_string(),
                cache: cache_actor_addr,
            }
        )
    }

    pub fn new_twilio(twilio_account_sid: &str, twilio_auth_token: &str, twilio_verify_sid: &str) -> Self {
        let client = awc::ClientBuilder::new()
            .basic_auth(
                twilio_account_sid,
                Some(twilio_auth_token)
            )
            .finish();

        Self::Twilio(
            client,
            TwilioServiceConfig {
                base_url: "https://verify.twilio.com/v2/Services".to_string(),
                verify_sid: twilio_verify_sid.to_string(),
            }
        )
    }

    pub fn new_infobip(base_url: &str, api_key: &str, twofa_app_id: &str, twofa_message_template_id: &str, cache_actor_addr: Addr<DragonflyService>) -> Self {
        let client = awc::ClientBuilder::new()
            .add_default_header(("authorization", api_key))
            .finish();

        Self::Infobip(
            client,
            InfobipServiceConfig {
                base_url: base_url.to_string(),
                twofa_app_id: twofa_app_id.to_string(),
                twofa_message_template_id: twofa_message_template_id.to_string(),
                cache: cache_actor_addr,
            }
        )
    }

    pub fn new_generic(url: &str, http_method: &str, http_template_body: &str, cache_actor_addr: Addr<DragonflyService>, http_headers: Option<HashMap<String, String>>) -> Self {
        let mut client = awc::ClientBuilder::new();

        if let Some(headers) = http_headers {
            for h in headers {
                client = client.add_default_header(h);
            }
        }

        Self::Generic(
            client.finish(),
            GenericServiceConfig {
                url: url.to_string(),
                http_method: http_method.to_string(),
                http_body_template: http_template_body.to_string(),
                cache: cache_actor_addr,
            }
        )
    }
}

impl SMSOtp for CoreSMSOtp {
    fn send(&self, to: &str) -> Pin<Box<dyn futures::Future<Output = Result<SMSOtpResult, SMSOtpError>> + '_>> {
        let to = to.to_string();

        match self {
            Self::Mock() => {
                Box::pin(async {
                    Ok(SMSOtpResult::SendResult(true))
                })
            },
            Self::Plasgate(client, config) => {
                Box::pin(async move {
                    let pin = nanoid!(6, &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']);

                    config.cache
                        .send(crate::dragonfly::DragonflyCommand::Set(
                            to.clone(),
                            pin.clone(),
                            redis::SetOptions::default().with_expiration(redis::SetExpiry::EX(960))
                        ))
                        .await??;

                    let mut resp = client
                        .post(format!("{}/rest/send?private_key={}", &config.base_url, &config.private_key))
                        .send_json(&serde_json::json!({
                            "to": to,
                            "sender": &config.sender_name,
                            "content": format!("Your OTP code is - {}", pin)
                        }))
                        .await?;

                    if resp.status() == StatusCode::OK {
                        return Ok(SMSOtpResult::SendResult(true));
                    }

                    tracing::error!(
                        "fail to send otp code: {:?}",
                        resp.body()
                            .await?
                    );

                    Err(SMSOtpError::FailToSendCode(format!("plasgate error: {}", resp.status())))
                })
            },
            Self::Twilio(client, config) => {
                Box::pin(async {
                    let mut resp = client
                        .post(format!("{}/{}/Verifications", &config.base_url, &config.verify_sid))
                        .send_form(&[("To", to), ("Channel", "sms".to_string())])
                        .await?;

                    if resp.status() == StatusCode::OK {
                        return Ok(SMSOtpResult::SendResult(true));
                    }

                    tracing::error!(
                        "fail to send otp code: {:?}",
                        resp.body()
                            .await?
                    );

                    Err(SMSOtpError::FailToSendCode(format!("twilio error: {}", resp.status())))
                })
            },
            Self::Infobip(client, config) => {
                Box::pin(async move {
                    let mut resp = client
                        .post(format!("{}/2fa/2/pin", &config.base_url))
                        .send_json(&serde_json::json!({
                            "to": to,
                            "application_id": &config.twofa_app_id,
                            "message_id": &config.twofa_message_template_id,
                        }))
                        .await?;

                    if resp.status() == StatusCode::OK {
                        let data = resp
                            .json::<serde_json::Value>()
                            .await?;

                        config.cache
                            .send(crate::dragonfly::DragonflyCommand::Set(to, data["pinId"].to_string(), redis::SetOptions::default().with_expiration(redis::SetExpiry::EX(960))))
                            .await??;

                        return Ok(SMSOtpResult::SendResult(true));
                    }

                    tracing::error!(
                        "fail to send otp code: {:?}",
                        resp.body()
                            .await?
                    );

                    Err(SMSOtpError::FailToSendCode(format!("infobip error: {}", resp.status())))
                })
            },
            CoreSMSOtp::Generic(client, generic_service_config) => {
                Box::pin(async move {
                    let pin = nanoid!(6, &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']);

                    generic_service_config.cache
                        .send(crate::dragonfly::DragonflyCommand::Set(
                            to.clone(),
                            pin.clone(),
                            redis::SetOptions::default().with_expiration(redis::SetExpiry::EX(960))
                        ))
                        .await??;

                    let req_body = rs_jsonnet::evaluator::pure::evaluate_with_tla(
                        &generic_service_config.http_body_template,
                        HashMap::from([
                            (
                                "ctx".to_string(),
                                serde_json::json!({
                                    "to": to,
                                    "otp": pin,
                                }).to_string(),
                            )
                        ])
                    )
                        .expect("failed to parse generic sms otp body template");

                    let mut resp = client
                        .request(
                            awc::http::Method::from_str(&generic_service_config.http_method)
                                .expect("failed to parse http method"),
                            &generic_service_config.url
                        )
                        .send_json(&req_body.to_json_value())
                        .await?;

                    if resp.status() == StatusCode::OK || resp.status() == StatusCode::NO_CONTENT {
                        return Ok(SMSOtpResult::SendResult(true));
                    }

                    Err(SMSOtpError::FailToSendCode(format!("failed to send generic sms otp error: {}, {:?}", resp.status(), resp.body().await?)))
                })
            },
        }
    }

    fn verify(&self, to: &str, code: &str) -> Pin<Box<dyn futures::Future<Output = Result<SMSOtpResult, SMSOtpError>> + '_>> {
        let to = to.to_string();
        let code = code.to_string();

        match self {
            Self::Mock() => {
                Box::pin(async move {
                    Ok(SMSOtpResult::VerifyResult(code == "000000"))
                })
            },
            Self::Plasgate(..) | Self::Generic(..) => {
                Box::pin(async move {
                    let res = self.get_cache()
                        .send(crate::dragonfly::DragonflyCommand::Get(to.clone()))
                        .await??;

                    if let Some(pin) = res {
                        return Ok(SMSOtpResult::VerifyResult(pin == code))
                    }

                    tracing::warn!("otp does not exists for {}", to);

                    Err(SMSOtpError::FailToVerifyCode("invalid otp code".to_string()))
                })
            },
            Self::Twilio(client, config) => {
                Box::pin(async move {
                    let mut resp = client
                        .post(format!("{}/{}/VerificationCheck", &config.base_url, &config.verify_sid))
                        .send_form(&[("To", to.clone()), ("Code", code)])
                        .await?;

                    if resp.status() == StatusCode::OK {
                        let result = resp
                            .json::<serde_json::Value>()
                            .await?;

                        return Ok(SMSOtpResult::VerifyResult(match (result.get("status"), result.get("valid")) {
                            (Some(status), Some(valid)) =>
                                status.as_str().expect("fail to access status field") == "approved" &&
                                valid.as_bool().expect("fail to access valid field"),
                            _ => false
                        }));
                    }

                    tracing::warn!(
                        "fail to verify otp for {} - {:?}",
                        to,
                        resp.body()
                            .await?
                    );

                    Err(SMSOtpError::FailToVerifyCode(format!("twilio error: {}", resp.status())))
                })
            },
            Self::Infobip(client, config) => {
                Box::pin(async move {
                    let res = config.cache
                        .send(crate::dragonfly::DragonflyCommand::Get(to))
                        .await??;

                    if let Some(pin_id) = res {
                        let mut resp = client
                            .post(format!("{}/2fa/2/pin/{}/verify", &config.base_url, pin_id))
                            .send_json(&serde_json::json!({"pin": code}))
                            .await?;

                        if resp.status() == StatusCode::OK {
                            let result = resp
                                .json::<serde_json::Value>()
                                .await?;

                            return Ok(SMSOtpResult::VerifyResult(
                                if let Some(is_verified) = result.get("verified") {
                                    is_verified.is_boolean() && is_verified.as_bool().unwrap()
                                } else {
                                    false
                                }
                            ));
                        }

                        Err(SMSOtpError::FailToVerifyCode(format!("infobip error: {}", resp.status())))
                    } else {
                        Err(SMSOtpError::InvalidRequest(format!("invalid request")))
                    }
                })
            },
        }
    }
}

#[derive(Message, Debug)]
#[rtype(result = "Result<SMSOtpResult, SMSOtpError>")]
pub enum CoreSMSOtpCommand {
    Send(String),
    Verify(String, String),
}

impl Handler<CoreSMSOtpCommand> for CoreSMSOtp {
    type Result = ResponseFuture<Result<SMSOtpResult, SMSOtpError>>;

    fn handle(&mut self, msg: CoreSMSOtpCommand, _ctx: &mut Self::Context) -> Self::Result {
        let this = self.clone();

        Box::pin(async move {
            match msg {
                CoreSMSOtpCommand::Send(to) => {
                    this.send(&to).await
                },
                CoreSMSOtpCommand::Verify(to, code) => {
                    this.verify(&to, &code).await
                },
            }
        })
    }
}

impl Actor for CoreSMSOtp {
    type Context = Context<Self>;

    fn start(self) -> actix::Addr<Self>
    where
        Self: Actor<Context = actix::Context<Self>>,
    {
        actix::Context::new().run(self)
    }
}
