use std::pin::Pin;

use awc::http::StatusCode;
use actix::{Actor, Context, Message, Handler, ResponseFuture};

pub enum SMSOtpError {
    FailToSendCode(String),
    FailToVerifyCode(String),
    UnknownError(String),
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
    verify_url: String,
}

#[derive(Clone)]
pub enum CoreSMSOtp {
    Twilio(awc::Client, TwilioServiceConfig),
}

impl CoreSMSOtp {
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
                verify_url: format!("https://verify.twilio.com/v2/Services/{twilio_verify_sid}"),
            }
        )
    }
}

impl SMSOtp for CoreSMSOtp {
    fn send(&self, to: &str) -> Pin<Box<dyn futures::Future<Output = Result<SMSOtpResult, SMSOtpError>> + '_>> {
        match self {
            Self::Twilio(client, config) => {
                let to = String::from(to);

                Box::pin(async {
                    let resp =
                        client
                            .post(format!("{}/Verifications", &config.verify_url))
                            .send_form(&[("To", to), ("Channel", "sms".to_string())])
                            .await?;

                    if resp.status() == StatusCode::OK {
                        return Ok(SMSOtpResult::SendResult(true));
                    }

                    Err(SMSOtpError::FailToSendCode("unknown".to_string()))
                })
            }
        }
    }

    fn verify(&self, to: &str, code: &str) -> Pin<Box<dyn futures::Future<Output = Result<SMSOtpResult, SMSOtpError>> + '_>> {
        match self {
            Self::Twilio(client, config) => {
                let to = String::from(to);
                let code = String::from(code);

                Box::pin(async {
                    let mut resp =
                        client
                            .post(format!("{}/VerificationCheck", &config.verify_url))
                            .send_form(&[("To", to), ("Code", code)])
                            .await?;

                    if resp.status() == StatusCode::OK {
                        let result = resp.json::<serde_json::Value>().await?;

                        return Ok(SMSOtpResult::VerifyResult(match (result.get("status"), result.get("valid")) {
                            (Some(status), Some(valid)) =>
                                status.as_str().expect("fail to access status field") == "approved" &&
                                valid.as_bool().expect("fail to access valid field"),
                            _ => false
                        }))
                    }

                    Err(SMSOtpError::FailToVerifyCode("unknown".to_string()))
                })
            }
        }
    }
}

#[derive(Message)]
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
