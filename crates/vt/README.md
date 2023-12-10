## MalwareDB VirusTotal Client
[![Test](https://github.com/malwaredb/malwaredb-rs/actions/workflows/test.yml/badge.svg)](https://github.com/malwaredb/malwaredb-rs/actions/workflows/test.yml)[![Lint](https://github.com/malwaredb/malwaredb-rs/actions/workflows/lint.yml/badge.svg)](https://github.com/malwaredb/malwaredb-rs/actions/workflows/lint.yml)[![Cross](https://github.com/malwaredb/malwaredb-rs/actions/workflows/cross.yml/badge.svg)](https://github.com/malwaredb/malwaredb-rs/actions/workflows/cross.yml)

This is logic for interacting with [VirusTotal](https://www.virustotal.com)'s [V3 API](https://virustotal.readme.io/reference/overview). At present, only the following actions are supported:
* Fetch file report: this gets the anti-virus scan data for a given sample, and there are examples in the `testdata/` directory.
* Request re-scan: ask VirusTotal to run a given sample through their collection of anti-virus applications and analysis tools.

VirusTotal supports these actions given a MD5, SHA-1, or SHA-256 hash.

Crates `chrono` and `serde` are used to deserialize the data into Structs for ease and convenience of working with this data.
