use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Smtp {
    #[serde(flatten)]
    pub event_fields: super::EventFields,
    pub info: SmtpInfo,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SmtpInfo {
    pub helo: String,
    pub mail_from: String,
    pub rcpt_to: Vec<String>,
}
