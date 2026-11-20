//! Finite production ContextDag state projection; sanitizer validity is assumed.
use enclave_agent_runtime::context_dag::ContextDag;
use enclave_core::label::{Conf, Taint};

/// Evaluate all bounded graph admission and endorsement-update cases.
pub fn decisions() -> Vec<String> {
    let levels = [Taint::T0, Taint::T1, Taint::T2, Taint::T3];
    let mut parent_sets = vec![vec![]];
    for a in levels { parent_sets.push(vec![a]); }
    for a in levels { for b in levels { parent_sets.push(vec![a, b]); } }
    for a in levels { for b in levels { for c in levels { parent_sets.push(vec![a, b, c]); } } }
    parent_sets.push(vec![]); // final domain is an unknown parent identifier
    let mut rows = Vec::with_capacity(3440);
    for (parent_index, parents) in parent_sets.iter().enumerate() {
        for explicit_index in 0..5 {
            for conf in [Conf::C1, Conf::C2, Conf::C3, Conf::C4] {
                for sanitize in [false, true] {
                    let mut graph = ContextDag::new();
                    let mut ids = Vec::new();
                    for taint in parents {
                        ids.push(graph.add_node(vec![], conf, Some(*taint), [1; 32]).unwrap());
                    }
                    if parent_index == 85 { ids.push(99999); }
                    let explicit = if explicit_index == 0 { None } else { Some(levels[explicit_index - 1]) };
                    let (error, integrity, sanitized) = match graph.add_node(ids.clone(), conf, explicit, [0; 32]) {
                        Ok(id) => {
                            if sanitize { graph.sanitize_node(id, [0xa5; 32]).unwrap(); }
                            let node = graph.get_node(id).unwrap();
                            assert_eq!(node.parents, ids);
                            assert_eq!(node.confidentiality, conf);
                            assert_eq!(node.content_hash, if sanitize { [0xa5; 32] } else { [0; 32] });
                            (0, node.integrity.rank(), u8::from(node.is_sanitized))
                        }
                        Err(e) if e.is("INTEGRITY_VIOLATION") => (1, 255, 0),
                        Err(e) if e.is("UNKNOWN_PARENT_NODE") => (2, 255, 0),
                        Err(e) => panic!("unexpected graph error: {e}"),
                    };
                    rows.push(format!("G,{},{parent_index},{explicit_index},{},{},{error},{integrity},{sanitized}",
                        rows.len(), conf.rank(), u8::from(sanitize)));
                }
            }
        }
    }
    assert_eq!(rows.len(), 3440);
    rows
}
