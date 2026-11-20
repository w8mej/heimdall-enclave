//! Compare actual production Cedar requests/policies with the compiled model.
//! Synthetic policies do not establish signed-bundle or caller authority.
use enclave_agent_runtime::cedar_engine::{CallFacts, CedarAction, CedarEngine, ToolResource, DEFAULT_SCHEMA};
use enclave_core::label::{Conf, Label, Taint};
use enclave_core::profile::{ActionClass, Profile};

/// Evaluate every bounded request through the production Cedar API.
pub fn decisions() -> Vec<String> {
    let mut decisions = Vec::with_capacity(7104);
    let predicates = ["true", "context.input_t <= 1", "context.input_c <= 2",
        "action == depot::Action::\"InvokeTool\"", "context.target_namespace == resource.namespace"];
    let mut sets = vec![vec![]];
    for first in 0..10 { sets.push(vec![first]); }
    for first in 0..10 { for second in 0..10 { sets.push(vec![first, second]); } }
    let mut row = 0;
    for (set_index, rules) in sets.iter().enumerate() {
        let source = rules.iter().enumerate().map(|(id, rule)| {
            let effect = if *rule < 5 { "permit" } else { "forbid" };
            format!("@id(\"vector{id}\")\n{effect}(principal, action in [depot::Action::\"InvokeTool\", depot::Action::\"DeclassifyEnum\"], resource) when {{ {} }};\n", predicates[*rule % 5])
        }).collect::<String>();
        let engine = CedarEngine::load(DEFAULT_SCHEMA, &source).expect("synthetic policy must validate");
        let tool = ToolResource { name: "depot://correspondence/read".into(), action_class: ActionClass::A1,
            sink_clearance: Conf::C4, namespace: "dev".into(), mutates_root: false };
        for (taint_index, taint) in [Taint::T0, Taint::T1, Taint::T2, Taint::T3].into_iter().enumerate() {
            for (conf_index, conf) in [Conf::C1, Conf::C2, Conf::C3, Conf::C4].into_iter().enumerate() {
                for (action_index, action) in [CedarAction::InvokeTool, CedarAction::DeclassifyEnum].into_iter().enumerate() {
                    for namespace_index in 0..2 {
                        let facts = CallFacts { input: Label::new(conf, taint), ast_taint: taint.rank(), row_count: 1,
                            qif_mb: 0, profile: Profile::L2, hw_grant: false,
                            target_namespace: if namespace_index == 0 { "dev" } else { "prod" }.into() };
                        // Validate the encoded request and exercise the actual
                        // public decision path, including cached entities.
                        engine.build("correspondence", 0, action, &tool, &facts, true).unwrap();
                        let (allow, reasons) = engine.is_authorized("correspondence", 0, action, &tool, &facts).unwrap();
                        assert!(!reasons.iter().any(|r| r == "EVALUATION_ERROR"));
                        decisions.push(format!("C,{row},{set_index},{taint_index},{},{action_index},{namespace_index},{}", conf_index + 1, u8::from(allow)));
                        row += 1;
                    }
                }
            }
        }
    }
    assert_eq!(row, 7104);
    decisions
}
