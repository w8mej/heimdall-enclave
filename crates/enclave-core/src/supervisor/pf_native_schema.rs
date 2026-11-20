//! Narrow output interpretation for one observed Darwin pfctl binary.
//! All values here are component observations, never an enforcement permit.
use sha2::{Digest, Sha256};

pub(super) const TOOL_PATH: &str = "/sbin/pfctl";
pub(super) const TOOL_SIZE: u64 = 483360;
pub(super) const TOOL_SHA256: &str =
    "675449d18fdca83c4e892b719215832092f8362d193fe9c72cd230918b5d150b";
const MAX_STREAM: usize = 1024 * 1024;
const MAX_LINES: usize = 4096;
const MAX_LINE: usize = 4096;

// Actual UID501 no-load parse receipt: coordinator/native-pf-canonical-parse-
// attempt3.stdout SHA256 5d6928f418326d1b00ec3d9c348fffdad654cb8d25148a570273b8d550053690.
// Exact immutable asset hashes and this tool identity are checked separately.
pub(super) const OBSERVED_LLM_COMPILE: &str = "loopback_if = \"lo0\"\nllm_group = \"_llmagent\"\npass out quick on lo0 inet proto tcp from any to 127.0.0.1 port = 8443 group = 8701 flags S/SA keep state\npass out quick on lo0 inet proto tcp from any to 127.0.0.1 port = 11434 group = 8701 flags S/SA keep state\npass out quick on lo0 inet6 proto tcp from any to ::1 port = 8443 group = 8701 flags S/SA keep state\npass out quick on lo0 inet6 proto tcp from any to ::1 port = 11434 group = 8701 flags S/SA keep state\nblock drop out log (all) quick inet all group = 8701\nblock drop out log (all) quick inet6 all group = 8701\n";
pub(super) const OBSERVED_CAS_COMPILE: &str = "cas_group = \"_enclavecas\"\nblock drop log (all) quick on lo0 inet proto tcp from any to 127.0.0.1 port = 2049 user = 501\nblock drop log (all) quick on lo0 inet6 proto tcp from any to ::1 port = 2049 user = 501\npass quick on lo0 inet proto tcp from any to 127.0.0.1 port = 2049 user = 0 flags S/SA keep state\npass quick on lo0 inet6 proto tcp from any to ::1 port = 2049 user = 0 flags S/SA keep state\nblock drop log (all) quick on lo0 proto tcp from any to any port = 2049\npass out quick proto tcp all group = 8702 flags S/SA keep state\npass out quick proto udp all group = 8702 keep state\n";
// Expected live form derived from actual canonical compiler output; kernel
// live output has NOT been observed by the UID501 no-load probe.
pub(super) const OBSERVED_LLM_RULES: &str = "pass out quick on lo0 inet proto tcp from any to 127.0.0.1 port = 8443 group = 8701 flags S/SA keep state\npass out quick on lo0 inet proto tcp from any to 127.0.0.1 port = 11434 group = 8701 flags S/SA keep state\npass out quick on lo0 inet6 proto tcp from any to ::1 port = 8443 group = 8701 flags S/SA keep state\npass out quick on lo0 inet6 proto tcp from any to ::1 port = 11434 group = 8701 flags S/SA keep state\nblock drop out log (all) quick inet all group = 8701\nblock drop out log (all) quick inet6 all group = 8701\n";
pub(super) const OBSERVED_CAS_RULES: &str = "block drop log (all) quick on lo0 inet proto tcp from any to 127.0.0.1 port = 2049 user = 501\nblock drop log (all) quick on lo0 inet6 proto tcp from any to ::1 port = 2049 user = 501\npass quick on lo0 inet proto tcp from any to 127.0.0.1 port = 2049 user = 0 flags S/SA keep state\npass quick on lo0 inet6 proto tcp from any to ::1 port = 2049 user = 0 flags S/SA keep state\nblock drop log (all) quick on lo0 proto tcp from any to any port = 2049\npass out quick proto tcp all group = 8702 flags S/SA keep state\npass out quick proto udp all group = 8702 keep state\n";
pub(super) const COMPILE_ADVISORY: &[u8] = b"pfctl: Use of -f option, could result in flushing of rules\npresent in the main ruleset added by the system at startup.\nSee /etc/pf.conf for further details.\n\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    UnsupportedTool,
    Size,
    Encoding,
    UnknownLine,
    Channel,
    Status,
    RootPolicy,
    EmptyRules,
    UnexpectedRules,
    CanonicalMismatch,
    Incomplete,
    RootTranslationOutput,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Query {
    Info,
    RootRules,
    LlmRules,
    CasRules,
    CompileLlm,
    CompileCas,
    RootTranslations,
}

/// Private closed native schema. Production obtains it only from the actual
/// protected tool original; a version string/provider is never accepted.
pub(super) struct SupportedSchema {
    _private: (),
}
impl SupportedSchema {
    pub(super) fn from_original(hash: &[u8; 32], size: u64) -> Result<Self, Error> {
        if !cfg!(all(target_os = "macos", target_arch = "aarch64"))
            || size != TOOL_SIZE
            || hex::encode(hash) != TOOL_SHA256
        {
            return Err(Error::UnsupportedTool);
        }
        Ok(Self { _private: () })
    }
}
#[cfg(test)]
pub(super) fn fixture_schema() -> SupportedSchema {
    SupportedSchema { _private: () }
}

fn lines(bytes: &[u8]) -> Result<Vec<&str>, Error> {
    if bytes.len() > MAX_STREAM {
        return Err(Error::Size);
    }
    if !bytes.is_ascii()
        || bytes
            .iter()
            .any(|byte| byte.is_ascii_control() && !matches!(*byte, b'\n' | b'\t'))
    {
        return Err(Error::Encoding);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Encoding)?;
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() > MAX_LINES || lines.iter().any(|line| line.len() > MAX_LINE) {
        return Err(Error::Size);
    }
    Ok(lines
        .into_iter()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect())
}
fn clean_stderr(bytes: &[u8], compiled: bool) -> Result<(), Error> {
    // Exactly the actual observed advisory is allowed for this fixed -nvf
    // command. A read-only query must not emit it; no stderr is discarded.
    if (compiled && bytes == COMPILE_ADVISORY) || (!compiled && bytes.is_empty()) {
        Ok(())
    } else {
        Err(Error::Channel)
    }
}
fn normalize(line: &str) -> String {
    line.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
}
fn unsigned(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && text.parse::<u64>().is_ok()
}
fn rate(text: &str) -> bool {
    let Some(number) = text.strip_suffix("/s") else { return false; };
    let Some((whole, fraction)) = number.split_once('.') else { return false; };
    unsigned(whole)
        && !fraction.is_empty()
        && fraction.len() <= 6
        && fraction.bytes().all(|byte| byte.is_ascii_digit())
}
fn elapsed(text: &str) -> bool {
    let parts = text.split(':').collect::<Vec<_>>();
    parts.len() == 3
        && parts.iter().all(|part| part.len() == 2 && unsigned(part))
        && parts[0].parse::<u8>().is_ok_and(|value| value < 24)
        && parts[1..]
            .iter()
            .all(|part| part.parse::<u8>().is_ok_and(|value| value < 60))
}
/// A single status snapshot says nothing about state ownership, provenance,
/// later insertions, or whether any state can bypass the required policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StateCount {
    ZeroAtSnapshot,
    NonzeroAtSnapshot(u64),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Info {
    enabled: bool,
    states: StateCount,
}
fn info(stdout: &[u8], stderr: &[u8]) -> Result<Info, Error> {
    clean_stderr(stderr, false)?;
    let input = lines(stdout)?;
    let first = input
        .first()
        .ok_or(Error::Status)?
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    // Complete status line, not contains("Enabled"). Debug is descriptive.
    if first.len() != 8
        || first[0] != "Status:"
        || first[2] != "for"
        || !unsigned(first[3])
        || first[4] != "days"
        || !elapsed(first[5])
        || first[6] != "Debug:"
        || first[7].is_empty()
        || !first[7].bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(Error::Status);
    }
    let enabled = match first[1] {
        "Enabled" => true,
        "Disabled" => false,
        _ => return Err(Error::Status),
    };
    let mut state_header = false;
    let mut counters_header = false;
    let mut current = None;
    let mut seen = std::collections::BTreeSet::new();
    for line in input.into_iter().skip(1) {
        let line = normalize(line);
        if line == "State Table Total Rate" && !state_header && !counters_header {
            state_header = true;
            continue;
        }
        if line == "Counters" && state_header && current.is_some() && !counters_header {
            counters_header = true;
            continue;
        }
        if let Some(value) = line.strip_prefix("Hostid: 0x") {
            if state_header
                || !seen.insert("Hostid".to_owned())
                || value.len() != 8
                || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(Error::UnknownLine);
            }
            continue;
        }
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if !state_header {
            return Err(Error::UnknownLine);
        }
        if !counters_header
            && fields.len() == 3
            && fields[..2] == ["current", "entries"]
            && unsigned(fields[2])
            && current.is_none()
        {
            current = Some(fields[2].parse::<u64>().map_err(|_| Error::UnknownLine)?);
            continue;
        }
        let Some(name) = fields.first() else { return Err(Error::UnknownLine); };
        let allowed = if counters_header {
            [
                "match",
                "bad-offset",
                "fragment",
                "short",
                "normalize",
                "memory",
                "bad-timestamp",
                "congestion",
                "ip-option",
                "proto-cksum",
                "state-mismatch",
                "state-insert",
                "state-limit",
                "src-limit",
                "synproxy",
                "dummynet",
            ]
            .contains(name)
        } else {
            ["searches", "inserts", "removals"].contains(name)
        };
        if !allowed
            || fields.len() != 3
            || !unsigned(fields[1])
            || !rate(fields[2])
            || !seen.insert((*name).to_owned())
        {
            return Err(Error::UnknownLine);
        }
    }
    if !state_header || !counters_header || !seen.contains("match") {
        return Err(Error::Incomplete);
    }
    let states = match current.ok_or(Error::Incomplete)? {
        0 => StateCount::ZeroAtSnapshot,
        count => StateCount::NonzeroAtSnapshot(count),
    };
    Ok(Info { enabled, states })
}

/// A complete successful root-default `-s nat` command emitted no bytes in
/// either stream. This describes OUTPUT ONLY. Installed Apple userland source
/// and complete NAT/RDR/BINAT/NAT64/anchor enumeration are not established;
/// unmatched FreeBSD comparison source is never installed-platform authority.
/// No inference about translated existing states, skips, later writers or full
/// translation policy follows, even for EmptyAtSnapshot. Actual query-specific
/// empty-output reachability is unobserved: even a legitimate ALTQ/other
/// advisory on stderr conservatively refuses. No no-load advisory is accepted
/// as a query schema or silently discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RootTranslationOutput {
    EmptyAtSnapshot,
}
fn root_translations(stdout: &[u8], stderr: &[u8]) -> Result<RootTranslationOutput, Error> {
    if stdout.len() > MAX_STREAM || stderr.len() > MAX_STREAM {
        return Err(Error::Size);
    }
    clean_stderr(stderr, false)?;
    // Whitespace, headers, warnings, NAT rules and anchor references all refuse.
    // Never normalize/filter a nonempty stream into a successful absence.
    if !stdout.is_empty() {
        return Err(Error::RootTranslationOutput);
    }
    Ok(RootTranslationOutput::EmptyAtSnapshot)
}

fn root(stdout: &[u8], stderr: &[u8]) -> Result<(), Error> {
    clean_stderr(stderr, false)?;
    let input = lines(stdout)?
        .into_iter()
        .map(normalize)
        .collect::<Vec<_>>();
    // This intentionally proves only one completely understood root sequence.
    // Other anchors, quick passes, selectors, translations or unknown syntax
    // require explicit analysis; they are never discarded as harmless noise.
    if input
        != [
            "anchor \"com.enterprise.llm.isolation\" all",
            "anchor \"com.enterprise.cas.swarm\" all",
        ]
    {
        return Err(Error::RootPolicy);
    }
    Ok(())
}

struct Rules {
    lines: Vec<String>,
    sha256: [u8; 32],
}
impl std::fmt::Debug for Rules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedPfRules")
            .field("count", &self.lines.len())
            .field("sha256", &self.sha256)
            .finish()
    }
}
fn rules(stdout: &[u8], stderr: &[u8], compiled: bool, llm: bool) -> Result<Rules, Error> {
    clean_stderr(stderr, compiled)?;
    let mut parsed = Vec::new();
    let mut macros = std::collections::BTreeSet::new();
    for line in lines(stdout)? {
        let line = normalize(line);
        if compiled
            && ((llm
                && ["loopback_if = \"lo0\"", "llm_group = \"_llmagent\""].contains(&line.as_str()))
                || (!llm && line == "cas_group = \"_enclavecas\""))
        {
            if !macros.insert(line) {
                return Err(Error::UnknownLine);
            }
            continue;
        }
        if !line.starts_with("pass ") && !line.starts_with("block ") {
            return Err(Error::UnknownLine);
        }
        // Exact compiler/live token equality below preserves every rule token
        // and its order. Numeric identity avoids name-resolution ambiguity.
        let identity = if llm { "8701" } else { "8702" };
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        let mut has_group = false;
        for (index, field) in fields.iter().enumerate() {
            if *field == "group" {
                if fields.get(index + 1) != Some(&"=")
                    || fields.get(index + 2) != Some(&identity)
                    || has_group
                {
                    return Err(Error::UnexpectedRules);
                }
                has_group = true;
            }
            if *field == "user" {
                if llm
                    || fields.get(index + 1) != Some(&"=")
                    || !matches!(fields.get(index + 2), Some(&"0") | Some(&"501"))
                {
                    return Err(Error::UnexpectedRules);
                }
            }
        }
        if llm && !has_group {
            return Err(Error::UnexpectedRules);
        }
        parsed.push(line);
    }
    if parsed.is_empty() {
        return Err(Error::EmptyRules);
    }
    let expected = if llm {
        OBSERVED_LLM_COMPILE
    } else {
        OBSERVED_CAS_COMPILE
    };
    let expected_macros = expected
        .lines()
        .filter(|line| !line.starts_with("pass ") && !line.starts_with("block "))
        .map(normalize)
        .collect::<std::collections::BTreeSet<_>>();
    if compiled && macros != expected_macros {
        return Err(Error::UnknownLine);
    }
    let expected_rules = expected
        .lines()
        .filter(|line| line.starts_with("pass ") || line.starts_with("block "))
        .map(normalize)
        .collect::<Vec<_>>();
    if parsed != expected_rules {
        return Err(Error::CanonicalMismatch);
    }
    let sha256 = Sha256::digest(parsed.join("\n").as_bytes()).into();
    Ok(Rules {
        lines: parsed,
        sha256,
    })
}

/// Accumulated actual-output components. No raw stdout/stderr is retained or
/// debugged. The parent must invalidate these on any original/command refusal.
pub(super) struct Components {
    _schema: SupportedSchema,
    info: Option<Info>,
    root: bool,
    root_translation_output: Option<RootTranslationOutput>,
    llm_live: Option<Rules>,
    cas_live: Option<Rules>,
    llm_compile: Option<Rules>,
    cas_compile: Option<Rules>,
}
impl Components {
    pub(super) fn new(schema: SupportedSchema) -> Self {
        Self {
            _schema: schema,
            info: None,
            root: false,
            root_translation_output: None,
            llm_live: None,
            cas_live: None,
            llm_compile: None,
            cas_compile: None,
        }
    }
    /// Start another read-only sample while retaining the SAME admitted schema.
    /// Clears only output components; no new tool/schema authority is created.
    pub(super) fn clear_observations(&mut self) {
        self.info = None;
        self.root = false;
        self.root_translation_output = None;
        self.llm_live = None;
        self.cas_live = None;
        self.llm_compile = None;
        self.cas_compile = None;
    }
    pub(super) fn observe(
        &mut self,
        query: Query,
        stdout: &[u8],
        stderr: &[u8],
    ) -> Result<(), Error> {
        match query {
            Query::Info => self.info = Some(info(stdout, stderr)?),
            Query::RootRules => {
                root(stdout, stderr)?;
                self.root = true;
            }
            Query::LlmRules => self.llm_live = Some(rules(stdout, stderr, false, true)?),
            Query::CasRules => self.cas_live = Some(rules(stdout, stderr, false, false)?),
            Query::CompileLlm => self.llm_compile = Some(rules(stdout, stderr, true, true)?),
            Query::CompileCas => self.cas_compile = Some(rules(stdout, stderr, true, false)?),
            Query::RootTranslations => {
                // Refusal must not leave an earlier empty-output diagnostic.
                self.root_translation_output = None;
                self.root_translation_output = Some(root_translations(stdout, stderr)?);
            }
        }
        for (live, compiled) in [
            (&self.llm_live, &self.llm_compile),
            (&self.cas_live, &self.cas_compile),
        ] {
            if let (Some(live), Some(compiled)) = (live, compiled) {
                if live.lines != compiled.lines {
                    return Err(Error::CanonicalMismatch);
                }
            }
        }
        Ok(())
    }
    pub(super) fn root_translation_output(&self) -> Option<RootTranslationOutput> {
        self.root_translation_output
    }
    pub(super) fn enabled(&self) -> Option<bool> {
        self.info.map(|info| info.enabled)
    }
    pub(super) fn state_count(&self) -> Option<StateCount> {
        self.info.map(|info| info.states)
    }
    pub(super) fn root_linkage_order(&self) -> bool {
        self.root
    }
    pub(super) fn llm_equal(&self) -> bool {
        matches!((&self.llm_live, &self.llm_compile), (Some(live), Some(compiled)) if live.lines == compiled.lines)
    }
    pub(super) fn cas_equal(&self) -> bool {
        matches!((&self.cas_live, &self.cas_compile), (Some(live), Some(compiled)) if live.lines == compiled.lines)
    }
}

#[cfg(test)]
#[path = "pf_native_schema_tests.rs"]
mod tests;
