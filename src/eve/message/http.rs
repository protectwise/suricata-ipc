use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    pub http_refer: String,
    pub http_method: String,
    pub protocol: String,
    pub status: i32,
    pub length: i32,
    pub redirect: String,
    pub xff: String,
    pub http_request_body: String,
    pub http_response_body: String,
    pub http_port: i32,
    pub headers: HashMap<String, String>,
}
