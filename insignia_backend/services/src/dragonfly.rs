
use redis::{SetOptions, Commands};
use actix::{Message, Handler, Actor, Context};

use models::http_error::AppError;

#[derive(Message)]
#[rtype(result = "Result<Option<String>, AppError>")]
pub enum DragonflyCommand {
    Ping,
    Get(String),
    Del(String),
    Set(String, String, SetOptions),
}

pub struct DragonflyService {
    pub client: redis::Client,
}

impl Actor for DragonflyService {
    type Context = Context<Self>;

    fn start(self) -> actix::Addr<Self>
    where
        Self: Actor<Context = Context<Self>>,
    {
        Context::new().run(self)
    }
}

impl Handler<DragonflyCommand> for DragonflyService {
    type Result = Result<Option<String>, AppError>;

    fn handle(&mut self, msg: DragonflyCommand, _ctx: &mut Self::Context) -> Self::Result {
        let mut conn = self.client
            .get_connection()
            .expect("fail to get dragonfly connection");

        let result = match msg {
            DragonflyCommand::Ping => conn.set::<&str, &str, String>("healthz", "set")?,
            DragonflyCommand::Get(key) => conn.get::<String, String>(key)?,
            DragonflyCommand::Del(key) => conn.del::<String, String>(key)?,
            DragonflyCommand::Set(key, value, opts) => conn.set_options::<String, String, String>(key, value, opts)?,
        };

        if result.is_empty() {
            return Ok(None)
        }

        Ok(Some(result))
    }
}
