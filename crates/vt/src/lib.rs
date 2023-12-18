pub mod filereport;
pub mod filerescan;

use crate::filereport::FileReportRequestResponse;
use crate::filerescan::FileRescanRequestResponse;

use std::fmt::{Display, Formatter};

use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::multipart::Form;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VirusTotalError {
    pub message: String,
    pub code: String,
}

impl Display for VirusTotalError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for VirusTotalError {}

#[derive(Clone)]
pub struct VirusTotalClient {
    key: Zeroizing<String>,
}

impl VirusTotalClient {
    const API_KEY: &'static str = "x-apikey";

    pub fn new(key: &str) -> Self {
        Self {
            key: Zeroizing::new(key.to_string()),
        }
    }

    fn header(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            VirusTotalClient::API_KEY,
            HeaderValue::from_str(&self.key).unwrap(),
        );
        headers
    }

    pub async fn get_report(&self, file_hash: &str) -> Result<FileReportRequestResponse> {
        let client = reqwest::Client::new();
        let body = client
            .get(format!(
                "https://www.virustotal.com/api/v3/files/{file_hash}"
            ))
            .headers(self.header())
            .send()
            .await?
            .bytes()
            .await?;

        let json_response = String::from_utf8(body.to_ascii_lowercase())
            .context("failed to convert response to string")?;
        let report: FileReportRequestResponse =
            serde_json::from_str(&json_response).context("failed to deserialize VT report")?;

        Ok(report)
    }

    pub async fn request_rescan(&self, file_hash: &str) -> Result<FileRescanRequestResponse> {
        let client = reqwest::Client::new();
        let body = client
            .post(format!(
                "https://www.virustotal.com/api/v3/files/{file_hash}/analyse"
            ))
            .headers(self.header())
            .header("content-length", "0")
            .send()
            .await?
            .bytes()
            .await?;

        let json_response = String::from_utf8(body.to_ascii_lowercase())
            .context("failed to convert response to string")?;
        let report: FileRescanRequestResponse = serde_json::from_str(&json_response)
            .context("failed to deserialize VT rescan request")?;

        Ok(report)
    }

    pub async fn submit(
        &self,
        data: Vec<u8>,
        name: Option<String>,
    ) -> Result<FileRescanRequestResponse> {
        let client = reqwest::Client::new();
        let form = if let Some(file_name) = name {
            Form::new().part(
                "file",
                reqwest::multipart::Part::bytes(data)
                    .file_name(file_name)
                    .mime_str("application/octet-stream")
                    .context("failed to set mime type")?,
            )
        } else {
            Form::new().part(
                "file",
                reqwest::multipart::Part::bytes(data)
                    .mime_str("application/octet-stream")
                    .context("failed to set mime type")?,
            )
        };

        let body = client
            .post("https://www.virustotal.com/api/v3/files")
            .headers(self.header())
            .header("accept", "application/json")
            .header("content-type", "multipart/form-data")
            .multipart(form)
            .send()
            .await?
            .bytes()
            .await?;
        let json_response = String::from_utf8(body.to_ascii_lowercase())
            .context("failed to convert response to string")?;
        let report: FileRescanRequestResponse = serde_json::from_str(&json_response)
            .context("failed to deserialize VT rescan request")?;

        Ok(report)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn api() {
        if let Ok(api_key) = std::env::var("VT_API_KEY") {
            const HASH: &str = "fff40032c3dc062147c530e3a0a5c7e6acda4d1f1369fbc994cddd3c19a2de88";

            let client = VirusTotalClient::new(&api_key);

            let report = client
                .get_report(HASH)
                .await
                .expect("failed to get or parse VT scan report");

            match report {
                FileReportRequestResponse::Data(data) => {
                    assert!(data.attributes.last_analysis_results.len() > 10);
                }
                FileReportRequestResponse::Error(error) => {
                    panic!("VT Report Error {error}");
                }
            }

            let rescan = client
                .request_rescan(HASH)
                .await
                .expect("failed to get or parse VT rescan response");

            match rescan {
                FileRescanRequestResponse::Data(data) => {
                    assert_eq!(data.rescan_type, "analysis");
                }
                FileRescanRequestResponse::Error(error) => {
                    panic!("VT Rescan Error {error}");
                }
            }

            const ELF: &[u8] = include_bytes!("../../types/testdata/elf/elf_haiku_x86");
            client
                .submit(Vec::from(ELF), Some("elf_haiku_x86".to_string()))
                .await
                .unwrap();
        } else {
            panic!("`VT_API_KEY` not set!")
        }
    }
}
