//! Typed recovery of per-block PoP-Biscuit facts (DEFECT-F-77).
//!
//! Earlier code recovered `pop_holder(k, pk, cb)` and `policy_bundle_blake3(h)`
//! by string-splitting `Biscuit::print_block_source`. That depended on the
//! printer's exact format and on no string term containing the same token
//! sequence. This module instead reads each block's **typed** Datalog
//! (`datalog::Fact` / `datalog::Check` with `Term::Integer` / `Term::Bytes`)
//! from the authorizer snapshot of the signature-verified token, and
//! cross-checks the holder facts against the authorizer's own evaluated world
//! (`Authorizer::query_all`). No printed text is parsed.

use biscuit_auth::builder::{AuthorizerBuilder, CheckKind};
use biscuit_auth::datalog::{Binary, Expression, Fact, Op, Predicate, SymbolTable, Term};
use biscuit_auth::format::convert::proto_snapshot_block_to_token_block;
use biscuit_auth::{AuthorizerLimits, Biscuit};
use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};

/// `pop_holder(k, pk, cb)`.
pub(crate) type Holder = (i64, [u8; 32], [u8; 32]);

/// Typed facts of one token block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BlockFacts {
    /// Every `pop_holder` fact the block asserts.
    pub holders: Vec<Holder>,
    /// Every well-formed `policy_bundle_blake3(hex:32 bytes)` fact.
    pub policy_bundles: Vec<[u8; 32]>,
    /// Facts other than `pop_holder`, plus rules (checks are not counted).
    pub ambient: usize,
    /// Signed mTLS expiries: each `check if utc_epoch_ms($v), $v <= N`.
    pub mtls_expiries_ms: Vec<u64>,
}

const HOLDERS_QUERY: &str = "h($k, $pk, $cb) <- pop_holder($k, $pk, $cb)";

/// Read every block's typed facts and cross-check the holder facts with the
/// authorizer's evaluated world. Any mismatch fails closed.
pub(crate) fn typed_block_facts(
    token: &Biscuit,
    limits: AuthorizerLimits,
) -> EnclaveResult<Vec<BlockFacts>> {
    let mut authz = AuthorizerBuilder::new()
        .set_limits(limits)
        .build(token)
        .map_err(|e| err!(EACCES, "BISCUIT_INVALID", "{e}"))?;
    let world: Vec<(i64, Vec<u8>, Vec<u8>)> = authz
        .query_all(HOLDERS_QUERY)
        .map_err(|e| err!(EACCES, "POP_HOLDER_INVALID", "{e}"))?;
    let snap = authz
        .snapshot()
        .map_err(|e| err!(EACCES, "BISCUIT_INVALID", "{e}"))?;
    let symbols = SymbolTable::from(snap.world.symbols.clone())
        .map_err(|e| err!(EACCES, "BISCUIT_INVALID", "{e}"))?;
    if snap.world.blocks.len() != token.block_count() {
        fail!(EACCES, "BISCUIT_INVALID", "snapshot block count mismatch");
    }
    let blocks = snap
        .world
        .blocks
        .iter()
        .map(|sb| {
            let block = proto_snapshot_block_to_token_block(sb)
                .map_err(|e| err!(EACCES, "BISCUIT_INVALID", "{e}"))?;
            block_facts(&block.facts, block.rules.len(), &block.checks, &symbols)
        })
        .collect::<EnclaveResult<Vec<_>>>()?;
    cross_check_world(&blocks, &world)?;
    Ok(blocks)
}

fn block_facts(
    facts: &[Fact],
    rules: usize,
    checks: &[biscuit_auth::datalog::Check],
    symbols: &SymbolTable,
) -> EnclaveResult<BlockFacts> {
    let mut out = BlockFacts {
        ambient: rules,
        ..BlockFacts::default()
    };
    for fact in facts {
        let p = &fact.predicate;
        match symbols.get_symbol(p.name) {
            Some("pop_holder") => out.holders.push(holder_of(p)?),
            Some("policy_bundle_blake3") => {
                if let [Term::Bytes(b)] = p.terms.as_slice() {
                    if let Ok(h) = <[u8; 32]>::try_from(b.as_slice()) {
                        out.policy_bundles.push(h);
                    }
                }
                out.ambient += 1;
            }
            _ => out.ambient += 1,
        }
    }
    out.mtls_expiries_ms = checks
        .iter()
        .filter(|c| c.kind == CheckKind::One)
        .filter_map(|c| match c.queries.as_slice() {
            [q] => mtls_expiry(&q.body, &q.expressions, symbols),
            _ => None,
        })
        .collect();
    Ok(out)
}

fn holder_of(p: &Predicate) -> EnclaveResult<Holder> {
    match p.terms.as_slice() {
        [Term::Integer(k), Term::Bytes(pk), Term::Bytes(cb)] => {
            let pk = <[u8; 32]>::try_from(pk.as_slice());
            let cb = <[u8; 32]>::try_from(cb.as_slice());
            match (pk, cb) {
                (Ok(pk), Ok(cb)) => Ok((*k, pk, cb)),
                _ => fail!(EACCES, "POP_HOLDER_MALFORMED"),
            }
        }
        _ => fail!(EACCES, "POP_HOLDER_MALFORMED"),
    }
}

/// Match exactly the shape `attenuate` emits for an mTLS clock caveat:
/// body `[utc_epoch_ms($v)]`, expression `[$v, N, <=]`. Other shapes are
/// ignored here (they still apply in Datalog); only exact matches count.
fn mtls_expiry(body: &[Predicate], exprs: &[Expression], symbols: &SymbolTable) -> Option<u64> {
    let [pred] = body else { return None };
    if symbols.get_symbol(pred.name) != Some("utc_epoch_ms") {
        return None;
    }
    let [Term::Variable(v)] = pred.terms.as_slice() else {
        return None;
    };
    let [expr] = exprs else { return None };
    match expr.ops.as_slice() {
        [Op::Value(Term::Variable(w)), Op::Value(Term::Integer(n)), Op::Binary(Binary::LessOrEqual)]
            if w == v =>
        {
            Some(u64::try_from(*n).unwrap_or(0))
        }
        _ => None,
    }
}

/// The evaluated world must contain exactly the holder facts the blocks
/// assert: no rule-derived holders, none the typed read missed.
fn cross_check_world(
    blocks: &[BlockFacts],
    world: &[(i64, Vec<u8>, Vec<u8>)],
) -> EnclaveResult<()> {
    let mut declared: Vec<(i64, Vec<u8>, Vec<u8>)> = blocks
        .iter()
        .flat_map(|b| b.holders.iter())
        .map(|(k, pk, cb)| (*k, pk.to_vec(), cb.to_vec()))
        .collect();
    let mut evaluated = world.to_vec();
    declared.sort();
    declared.dedup();
    evaluated.sort();
    evaluated.dedup();
    if declared != evaluated {
        fail!(
            EACCES,
            "POP_HOLDER_INVALID",
            "pop_holder facts in the evaluated world differ from the blocks' typed facts"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bf(holders: Vec<Holder>) -> BlockFacts {
        BlockFacts {
            holders,
            ..BlockFacts::default()
        }
    }

    #[test]
    fn cross_check_rejects_extra_or_missing_world_holders() {
        let h0 = (0, [1u8; 32], [2u8; 32]);
        let blocks = vec![bf(vec![h0])];
        let same = vec![(0, vec![1u8; 32], vec![2u8; 32])];
        assert!(cross_check_world(&blocks, &same).is_ok());
        let extra = vec![same[0].clone(), (1, vec![9u8; 32], vec![9u8; 32])];
        assert!(cross_check_world(&blocks, &extra)
            .unwrap_err()
            .is("POP_HOLDER_INVALID"));
        assert!(cross_check_world(&blocks, &[])
            .unwrap_err()
            .is("POP_HOLDER_INVALID"));
    }
}
