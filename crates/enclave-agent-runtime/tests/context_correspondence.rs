//! Bounded production graph/model correspondence with explicit sanitizer limits.
#[path = "../examples/context_correspondence_support/mod.rs"]
mod production;

#[test]
fn actual_context_dag_matches_pinned_lean_projection() {
    let expected: Vec<_> = include_str!("data/context-lean-4.14.0.csv").lines().collect();
    let actual = production::decisions();
    assert_eq!(expected.len(), 3440);
    assert_eq!(actual.len(), expected.len());
    for (index, (actual, model)) in actual.iter().zip(expected).enumerate() {
        assert_eq!(actual, model, "ContextDag/model disagreement at row{index}");
    }
    eprintln!("F146 matched3440 production ContextDag cases; sanitizer trust and caller policy remain outside the model");
}
