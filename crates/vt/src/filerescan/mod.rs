use crate::VirusTotalError;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum FileRescanRequestResponse {
    #[serde(rename = "data")]
    Data(FileRescanRequestData),
    #[serde(rename = "error")]
    Error(VirusTotalError),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileRescanRequestData {
    #[serde(rename = "type")]
    pub rescan_type: String,

    pub id: String,

    pub links: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn deserialize_valid_response() {
        const RESPONSE: &str = include_str!("../../testdata/rescan.json");

        let rescan: FileRescanRequestResponse = serde_json::from_str(RESPONSE)
            .context("failed to deserialize VT rescan")
            .unwrap();

        if let FileRescanRequestResponse::Data(data) = rescan {
            assert_eq!(data.rescan_type, "analysis");
        } else {
            panic!("Rescan report shouldn't be an error type");
        }
    }
}
