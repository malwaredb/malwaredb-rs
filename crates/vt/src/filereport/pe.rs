use chrono::serde::ts_seconds_option;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Fields and information unique to PE32 files
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PEInfo {
    /// Rich Header, which may reveal compiler information
    #[serde(default)]
    pub rich_pe_header_hash: Option<String>,

    /// When the program was compiled, can be spoofed
    #[serde(default, with = "ts_seconds_option")]
    pub timestamp: Option<DateTime<Utc>>,

    #[serde(default)]
    pub compiler_product_versions: Vec<String>,

    /// Starting point for execution
    pub entry_point: u64,

    /// CPU target for this program
    pub machine_type: u32,

    /// Import hash
    /// https://www.mandiant.com/resources/blog/tracking-malware-import-hashing
    pub imphash: String,

    /// Section information
    #[serde(default)]
    pub sections: Vec<PESection>,

    /// Imports by .dll
    #[serde(default)]
    pub import_list: Vec<PEImports>,

    /// Anything else not capture by this struct
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
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
    #[serde(default)]
    pub imported_functions: Vec<String>,
}

pub mod dotnet {
    use super::*;
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct DotNetAssembly {
        pub entry_point_rva: u64,

        pub metadata_header_rva: u64,

        pub assembly_name: String,

        pub assembly_flags: u32,

        /// Relative Virtual Address of the strong name signature hash
        pub strongname_va: u32,

        pub tables_rows_map_log: String,

        pub external_assemblies: HashMap<String, ExternalAssembly>,

        #[serde(default)]
        pub type_definition_list: Vec<TypeDefinition>,

        pub entry_point_token: u64,

        pub tables_rows_map: String,

        pub assembly_flags_txt: String,

        pub streams: HashMap<String, Stream>,

        pub tables_present: u32,

        /// Hex value of present tables bitmap
        pub tables_present_map: String,

        /// Version of the Common Language Runtime
        pub clr_version: String,
        pub clr_meta_version: String,

        pub assembly_data: AssemblyData,

        /// Resources Virtual Address
        pub resources_va: u64,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ExternalAssembly {
        pub version: String,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct TypeDefinition {
        #[serde(default)]
        pub type_definitions: Vec<String>,
        pub namespace: String,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Stream {
        pub chi2: f32,
        pub size: u64,
        pub entropy: f32,
        pub md5: String,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct AssemblyData {
        pub majorversion: u64,
        pub minorversion: u64,
        pub hashalgid: u64,
        pub flags_text: String,
        pub buildnumber: u64,
        pub flags: u64,
        pub revisionnumber: u64,
        pub name: String,
    }
}
