use serde::{Deserialize, Serialize};

/// Parsed information for ELF binaries
/// https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElfInfo {
    /// Shared libraries used
    #[serde(default)]
    pub shared_libraries: Vec<String>,

    /// ELF Sections
    #[serde(default)]
    pub section_list: Vec<ElfSection>,

    /// Details of the ELF header
    pub header: ElfHeader,

    /// Exported Symbols
    #[serde(default)]
    pub export_list: Vec<ElfImportExport>,

    /// Imported Symbols
    #[serde(default)]
    pub import_list: Vec<ElfImportExport>,

    /// ELF Segments
    #[serde(default)]
    pub segment_list: Vec<ElfSegment>,
}

/// Sections of an ELF binary
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElfSection {
    /// Section name
    #[serde(default)]
    pub name: String,

    /// Section type
    pub section_type: String,

    /// Section address in memory
    pub virtual_address: u64,

    /// Section location on disk
    pub physical_offset: u64,

    /// Section flags
    #[serde(default)]
    pub flags: String,

    /// Section size
    pub size: u64,
}

/// ELF header
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElfHeader {
    /// ELF version, should be 1
    pub hdr_version: String,

    /// ELF type, library, program, etc
    #[serde(rename = "type")]
    pub elf_type: String,

    pub obj_version: String,

    pub data: String,

    /// Instruction Set Architecture
    pub machine: String,

    /// Number of sections
    pub num_section_headers: u64,

    /// SystemV, FreeBSD, OpenBSD, etc
    pub os_abi: String,

    pub abi_version: u32,

    pub entrypoint: u64,

    /// Number of program headers
    pub num_prog_headers: u64,

    /// ELF32 or ELF64
    pub class: String,
}

/// Imported or Exported ELF symbols
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElfImportExport {
    #[serde(rename = "type")]
    pub export_type: String,
    pub name: String,
}

/// ELF Segment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElfSegment {
    pub segment_type: String,

    #[serde(default)]
    pub resources: Vec<String>,
}
