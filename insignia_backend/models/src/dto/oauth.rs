
#[derive(serde::Serialize, serde::Deserialize)]
pub enum OauthClientType {
    Public,
    Confidential,
}

impl ToString for OauthClientType {
    fn to_string(&self) -> String {
        match self {
            OauthClientType::Public => "public".to_string(),
            OauthClientType::Confidential => "confidential".to_string(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub enum OauthFlow {
    PKCE,
    ClientCredential,
}

impl ToString for OauthFlow {
    fn to_string(&self) -> String {
        match self {
            OauthFlow::PKCE => "pkce".to_string(),
            OauthFlow::ClientCredential => "client-credential".to_string(),
        }
    }
}

#[derive(serde::Deserialize)]
pub struct OauthClientMutationDto {
    pub name: String,
    pub label: Option<String>,
    pub authn_flow: OauthFlow,
    pub client_type: OauthClientType,
    pub audiences: Vec<String>,
    pub redirect_uris: Vec<String>,
}
