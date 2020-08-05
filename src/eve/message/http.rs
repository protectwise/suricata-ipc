use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Http {
    #[serde(flatten)]
    pub event_fields: super::EventFields,
    #[serde(rename = "http")]
    pub info: HttpInfo,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HttpInfo {
    pub hostname: String,
    pub url: String,
    pub http_user_agent: String,
    pub http_content_type: String,
    #[serde(default)]
    pub http_refer: String,
    #[serde(default)]
    pub http_method: String,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub status: i32,
    #[serde(default)]
    pub length: i32,
    #[serde(default)]
    pub redirect: String,
    #[serde(default)]
    pub xff: String,
    #[serde(default)]
    pub http_request_body: String,
    #[serde(default)]
    pub http_response_body: String,
    #[serde(default)]
    pub http_port: i32,
    #[serde(default)]
    pub request_headers: Vec<Header>,
    #[serde(default)]
    pub response_headers: Vec<Header>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}


