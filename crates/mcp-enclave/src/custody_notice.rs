//! User-visible L3 attestation risk notice at setup and enrollment entry points.

/// Stable notice shared with the packaged installer; contains no device identifiers.
pub const L3_ATTESTATION_NOTICE: &str =
    include_str!("../../../packaging/macos/l3-attestation-notice.txt");

/// Display the L3 input-policy tradeoff before setup effects, including JSON mode.
/// Repeated setup attempts show it again; no acknowledgement or secret is stored.
pub fn show_for_profile(profile: &str) {
    let _ = write_for_profile(profile, &mut std::io::stderr().lock());
}

/// Keep human disclosure on the diagnostic stream, including machine JSON mode.
/// A failed diagnostic write must not make setup panic or disclose to stdout.
pub fn write_for_profile(profile: &str, diagnostic: &mut impl std::io::Write) -> std::io::Result<()> {
    if profile.eq_ignore_ascii_case("L3") {
        diagnostic.write_all(L3_ATTESTATION_NOTICE.as_bytes())?;
    }
    Ok(())
}
