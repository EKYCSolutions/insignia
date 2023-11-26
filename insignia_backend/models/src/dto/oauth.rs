
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

#[derive(serde::Deserialize)]
pub struct UserOauthConsentApproveRequestDto {
    pub request_id: String,
    pub consents: Vec<UserOauthConsentObjectRequestDto>,
}

#[derive(serde::Deserialize)]
pub struct UserOauthConsentObjectRequestDto {
    pub oauth_scope_id: i32,
    pub zanzibar_subject: String,
    pub zanzibar_relative: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct UserOauthConsentResponse {
    pub client_id: String,
    pub request_id: String,
    pub subject: String,
    pub scope: Vec<String>,
    pub audience: Vec<String>,
}
