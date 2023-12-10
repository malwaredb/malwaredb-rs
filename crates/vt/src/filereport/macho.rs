use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Parsed formation for Mach-O binaries
/// https://en.wikipedia.org/wiki/Mach-O
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MachoInfo {
    /// Header of the Mach-O file
    pub headers: MachoHeader,

    /// Commands section
    pub commands: MachoCommands,

    /// Segments
    #[serde(default)]
    pub segments: Vec<MachoSegment>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MachoHeader {
    /// Magic number for the header
    pub magic: String,

    /// File type flag
    pub file_type: String,

    /// Size of the commands
    pub size_cmds: u32,

    /// Number of commands
    pub num_cmds: u32,

    /// Flags
    #[serde(default)]
    pub flags: Vec<String>,

    /// CPU type flag
    pub cpu_type: String,

    /// CPU sub-type (further details) flag
    pub cpu_subtype: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MachoCommands(pub Vec<HashMap<String, String>>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MachoSegment {
    /// Segment name
    pub name: String,

    /// File offset, hex string
    pub fileoff: String,

    /// Memory size, hex string
    pub vmsize: String,

    /// Memory address, hex string
    pub vmaddr: String,

    /// Sections in this segment
    #[serde(default)]
    pub sections: Vec<MachoSection>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MachoSection {
    #[serde(default)]
    pub flags: Vec<String>,
    pub name: String,

    #[serde(rename = "type")]
    pub section_type: String,
}
