use chrono::serde::ts_seconds;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Fields and information unique to PE32 files
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PEInfo {
    /// Rich Header, which may reveal compiler information
    pub rich_pe_header_hash: String,

    /// When the program was compiled, can be spoofed
    #[serde(with = "ts_seconds")]
    pub timestamp: DateTime<Utc>,

    pub compiler_product_versions: Vec<String>,

    /// Starting point for execution
    pub entry_point: u64,

    /// CPU target for this program
    pub machine_type: u32,

    /// Import hash
    /// https://www.mandiant.com/resources/blog/tracking-malware-import-hashing
    pub imphash: String,

    /// Section information
    pub sections: Vec<PESection>,

    /// Imports by .dll
    pub import_list: Vec<PEImports>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PESection {
    /// Section name
    pub name: String,

    /// Chi-Square metric
    pub chi2: f32,

    /// Address when loaded
    pub virtual_address: u64,

    /// Entropy
    pub entropy: f32,

    /// Size on disk
    pub raw_size: u64,

    /// Flags: executable, readable, writable
    pub flags: String,

    /// Size in memory
    pub virtual_size: u64,

    /// MD5 hash of the section
    pub md5: String,
}

/// Functions imported from a given .dll
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PEImports {
    /// .dll name
    pub library_name: String,

    /// Function names
    pub imported_functions: Vec<String>,
}
