//! Translation validation against an actually compiled pinned Lean corpus.
//! This covers finite engine/request decisions, not policy-bundle authority.
#[path = "../examples/authorization_correspondence_support/mod.rs"]
mod production;

#[test]
fn actual_cedar_engine_matches_pinned_lean_policy_domain() {
    let expected: Vec<_> = include_str!("data/cedar-lean-4.14.0.csv").lines().collect();
    let actual = production::decisions();
    assert_eq!(expected.len(), 7104, "complete ordered Lean domain required");
    assert_eq!(actual.len(), expected.len());
    for (index, (actual, model)) in actual.iter().zip(expected).enumerate() {
        assert_eq!(actual, model, "production Cedar/model disagreement at row{index}");
    }
    eprintln!("F143 matched7104 production Cedar decisions to compiled Lean4.14.0:111 policy lists,64 requests");
}
