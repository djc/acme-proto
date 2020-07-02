use serde::{self, Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryMeta {
    pub terms_of_service: Option<String>,
    pub website: Option<String>,
    pub caa_identities: Option<Vec<String>>,
    pub external_account_required: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub meta: Option<DirectoryMeta>,
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    pub new_authz: Option<String>,
    pub revoke_cert: String,
    pub key_change: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub contact: Vec<String>,
    pub terms_of_service_agreed: bool,
    pub only_return_existing: bool,
}

impl Account {
    pub fn new(cert: &Certificate) -> Self {
        Account {
            contact: vec![format!("mailto:{}", cert.account.email)],
            terms_of_service_agreed: cert.tos_agreed,
            only_return_existing: false,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountResponse {
    pub status: String,
    pub contact: Option<Vec<String>>,
    pub terms_of_service_agreed: Option<bool>,
    pub external_account_binding: Option<String>,
    pub orders: Option<String>,
}

#[derive(Deserialize)]
pub struct Authorization {
    pub identifier: Identifier,
    pub status: AuthorizationStatus,
    pub expires: Option<String>,
    pub challenges: Vec<Challenge>,
    pub wildcard: Option<bool>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationStatus {
    Pending,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
}

#[derive(PartialEq, Deserialize)]
#[serde(tag = "type")]
pub enum Challenge {
    #[serde(rename = "http-01")]
    Http01(TokenChallenge),
    #[serde(rename = "dns-01")]
    Dns01(TokenChallenge),
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01(TokenChallenge),
    #[serde(other)]
    Unknown,
}

#[derive(Deserialize, PartialEq)]
pub struct TokenChallenge {
    pub url: String,
    pub status: Option<ChallengeStatus>,
    pub validated: Option<String>,
    pub error: Option<HttpApiError>,
    pub token: String,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

#[derive(Serialize)]
pub struct NewOrder {
    pub identifiers: Vec<Identifier>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}

impl NewOrder {
    pub fn new(domains: &[String]) -> Self {
        NewOrder {
            identifiers: domains.iter().map(|n| Identifier::new_dns(n)).collect(),
            not_before: None,
            not_after: None,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    pub status: OrderStatus,
    pub expires: Option<String>,
    pub identifiers: Vec<Identifier>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub error: Option<HttpApiError>,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct Identifier {
    #[serde(rename = "type")]
    pub id_type: IdentifierType,
    pub value: String,
}

impl Identifier {
    pub fn new_dns(value: &str) -> Self {
        Identifier {
            id_type: IdentifierType::Dns,
            value: value.to_string(),
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum IdentifierType {
    #[serde(rename = "dns")]
    Dns,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AcmeError {
    r#type: String,
    detail: String,
    status: u16,
}
