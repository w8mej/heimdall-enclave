//! Export the actual AIR `eval` polynomials; no hand-written constraint model.
use enclave_zk_auditor::zk::{air, imt_air, lasso_dfa, merkle_air, poseidon2_air, sig_air};
use p3_air::symbolic::{
    get_symbolic_constraints, AirLayout, BaseEntry, BaseLeaf, SymbolicAirBuilder,
    SymbolicExpression,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;
use serde_json::{json, Value};

struct DeterministicControl;
impl<F> BaseAir<F> for DeterministicControl {
    fn width(&self) -> usize {
        2
    }
}
impl<AB: AirBuilder> Air<AB> for DeterministicControl {
    fn eval(&self, builder: &mut AB) {
        let window = builder.main();
        let input: AB::Expr = window.current(0).unwrap().into();
        let output: AB::Expr = window.current(1).unwrap().into();
        builder.assert_eq(output, input);
    }
}

fn expression(e: &SymbolicExpression<KoalaBear>) -> Value {
    match e {
        SymbolicExpression::Leaf(l) => match l {
            BaseLeaf::Constant(f) => json!(["constant", f.as_canonical_u32()]),
            BaseLeaf::Variable(v) => match v.entry {
                BaseEntry::Main { offset } => json!(["main", offset, v.index]),
                BaseEntry::Public => json!(["public", v.index]),
                other => panic!("unsupported variable: {other:?}"),
            },
            BaseLeaf::IsFirstRow => json!(["first"]),
            BaseLeaf::IsLastRow => json!(["last"]),
            BaseLeaf::IsTransition => json!(["transition"]),
        },
        SymbolicExpression::Add { x, y, .. } => json!(["add", expression(x), expression(y)]),
        SymbolicExpression::Sub { x, y, .. } => json!(["sub", expression(x), expression(y)]),
        SymbolicExpression::Mul { x, y, .. } => json!(["mul", expression(x), expression(y)]),
        SymbolicExpression::Neg { x, .. } => json!(["neg", expression(x)]),
    }
}

fn export<A: BaseAir<KoalaBear> + Air<SymbolicAirBuilder<KoalaBear>>>(
    air: &A,
    columns: Value,
) -> Value {
    let layout = AirLayout::from_air::<KoalaBear>(air);
    let constraints = get_symbolic_constraints::<KoalaBear, _>(air, layout);
    json!({"width": layout.main_width, "public_count": layout.num_public_values,
        "columns": columns, "constraints": constraints.iter().map(expression).collect::<Vec<_>>()})
}

fn main() {
    println!(
        "{}",
        json!({
            "prime": enclave_core::poseidon2::KOALABEAR_P,
        "DeterministicControl": export(&DeterministicControl, json!({})),
            "Poseidon2Air": export(&poseidon2_air::Poseidon2Air, json!({
                "active": poseidon2_air::col::ACTIVE, "output": poseidon2_air::col::STATE_OUT})),
            "MerkleAir": export(&merkle_air::MerkleAir, json!({
                "active": merkle_air::col::ACTIVE, "current": merkle_air::col::CURR,
                "sibling": merkle_air::col::SIBLING, "output": merkle_air::col::PARENT})),
            "SigAir": export(&sig_air::SigAir, json!({"active": sig_air::col::ACTIVE,
                "key": sig_air::col::K_MAC, "message": sig_air::col::M_DIGEST,
                "pk": sig_air::col::PK_LEAF, "output": sig_air::col::TAG})),
            "ImtAir": export(&imt_air::ImtAir, json!({"active": imt_air::col::ACTIVE,
                "target": imt_air::col::TARGET_VAL, "low": imt_air::col::LOW_VAL,
                "high": imt_air::col::HIGH_VAL, "output": imt_air::col::ROOT_CURR})),
            "LassoDfaAir": export(&lasso_dfa::LassoDfaAir, json!({"active": lasso_dfa::col::ACTIVE,
                "byte": lasso_dfa::col::BYTE, "digit": lasso_dfa::col::IS_DIGIT,
                "output": lasso_dfa::col::NEXT_STATE})),
            "EpochAir": export(&air::EpochAir, json!({"active": air::col::ACTIVE,
                "fold": air::col::IS_FOLD, "delta": air::col::DELTA,
                "used": air::col::USED, "slack": air::col::SLACK, "bits": air::BITS,
                "used_bits": air::col::UBITS, "delta_bits": air::col::DBITS,
                "cap_public": air::pv::CAP})),
        })
    );
}
