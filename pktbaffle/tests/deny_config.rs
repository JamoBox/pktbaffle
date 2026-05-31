/// Regression test: deny.toml must not contain the removed [licenses].deny key.
///
/// cargo-deny removed [licenses].deny in https://github.com/EmbarkStudios/cargo-deny/pull/611.
/// Any license not present in the `allow` list is already implicitly denied, so the explicit
/// `deny` list is both redundant and a hard error under current cargo-deny versions.
#[test]
fn deny_toml_licenses_section_has_no_deny_key() {
    let deny_toml = include_str!("../../deny.toml");

    let licenses_start = deny_toml
        .find("[licenses]")
        .expect("deny.toml must contain a [licenses] section");

    let after_licenses = &deny_toml[licenses_start + "[licenses]".len()..];
    let section_end = after_licenses.find("\n[").unwrap_or(after_licenses.len());
    let licenses_section = &after_licenses[..section_end];

    assert!(
        !licenses_section.contains("deny = ["),
        "deny.toml [licenses] section contains a 'deny = [' key that was \
         removed from cargo-deny (EmbarkStudios/cargo-deny#611). \
         Delete the deny list — licenses absent from the allow list are implicitly denied."
    );
}
