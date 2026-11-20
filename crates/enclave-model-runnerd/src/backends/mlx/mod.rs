//! Reference operator-family callback fixture. This does not load MLX, inspect
//! framework graphs, or establish which operators a real model executes.

use enclave_core::error::EnclaveResult;
use enclave_core::fail;
use std::os::raw::{c_int, c_void};

use crate::topology::{OpAttestor, OpFamily};

/// `mlx_eagle3_v1` artifact format and native-worker speculative backend.
pub mod eagle3;
/// `mlx_llada_v1` artifact format (quantized LLaDA masked diffusion).
pub mod llada;
/// `mlx_llama_v1` artifact format and native-worker backend.
pub mod llama;
/// Real fixed-graph CPU MLX worker, kept separate from reference callback shims.
pub mod runtime;
/// `mlx_rwkv7_v1` artifact format and native-worker recurrent backend.
pub mod rwkv7;
/// `mlx_vjepa2_v1` artifact format and native-worker world-model backend.
pub mod vjepa2;

extern "C" {
    fn mlx_construct_operator(
        op_family: c_int,
        hook: Option<extern "C" fn(c_int, *mut c_void) -> c_int>,
        context: *mut c_void,
    ) -> c_int;
    fn mlx_construct_graph(
        op_families: *const c_int,
        count: libc::size_t,
        hook: Option<extern "C" fn(c_int, *mut c_void) -> c_int>,
        context: *mut c_void,
    ) -> c_int;
}

fn to_c_int(op: OpFamily) -> c_int {
    match op {
        OpFamily::CausalDecode => 0,
        OpFamily::ClassifierHead => 1,
        OpFamily::BidirectionalMask => 2,
        OpFamily::DenoiseStep => 3,
        OpFamily::PersistentStateScan => 4,
        OpFamily::ByteDecode => 5,
        OpFamily::ConceptDiffusion => 6,
        OpFamily::RecurrentDepthLoop => 7,
        OpFamily::DraftTree => 8,
        OpFamily::JepaPredict => 9,
        OpFamily::MpcRollout => 10,
    }
}

fn from_c_int(raw: c_int) -> Option<OpFamily> {
    match raw {
        0 => Some(OpFamily::CausalDecode),
        1 => Some(OpFamily::ClassifierHead),
        2 => Some(OpFamily::BidirectionalMask),
        3 => Some(OpFamily::DenoiseStep),
        4 => Some(OpFamily::PersistentStateScan),
        5 => Some(OpFamily::ByteDecode),
        6 => Some(OpFamily::ConceptDiffusion),
        7 => Some(OpFamily::RecurrentDepthLoop),
        8 => Some(OpFamily::DraftTree),
        9 => Some(OpFamily::JepaPredict),
        10 => Some(OpFamily::MpcRollout),
        _ => None,
    }
}

struct AttestContext<'a> {
    attest: &'a mut OpAttestor,
    failed_op: Option<OpFamily>,
}

extern "C" fn attest_trampoline(op_raw: c_int, ctx_ptr: *mut c_void) -> c_int {
    if ctx_ptr.is_null() {
        return -1;
    }
    // SAFETY: ctx_ptr is exclusively borrowed by the enclosing construct_and_attest call.
    let ctx = unsafe { &mut *(ctx_ptr as *mut AttestContext<'_>) };
    let op = match from_c_int(op_raw) {
        Some(o) => o,
        None => return -2,
    };
    if let Err(_e) = ctx.attest.admit(op) {
        ctx.failed_op = Some(op);
        return -3; // Denied by OpAttestor
    }
    0 // Admitted
}

/// Check one caller-declared reference operator family.
pub fn construct_operator_and_attest(attest: &mut OpAttestor, op: OpFamily) -> EnclaveResult<()> {
    let mut ctx = AttestContext {
        attest,
        failed_op: None,
    };
    let ctx_ptr = &mut ctx as *mut _ as *mut c_void;
    let c_op = to_c_int(op);

    // SAFETY: Registering trampoline and constructing single operator.
    unsafe {
        let rc = mlx_construct_operator(c_op, Some(attest_trampoline), ctx_ptr);

        if rc != 0 {
            if let Some(failed) = ctx.failed_op {
                fail!(
                    EACCES,
                    "GRAPH_OP_NOT_AUTHORISED",
                    "{failed:?} not authorised by the signed ExecutionClass"
                );
            } else {
                fail!(
                    EACCES,
                    "GRAPH_OP_NOT_AUTHORISED",
                    "operator rejected by MLX shim hook"
                );
            }
        }
    }

    Ok(())
}

/// Check a caller-declared reference operator list; no compute graph is constructed.
pub fn construct_and_attest(attest: &mut OpAttestor, ops: &[OpFamily]) -> EnclaveResult<()> {
    let mut ctx = AttestContext {
        attest,
        failed_op: None,
    };
    let ctx_ptr = &mut ctx as *mut _ as *mut c_void;

    let c_ops: Vec<c_int> = ops.iter().copied().map(to_c_int).collect();

    // SAFETY: Registering the trampoline and executing the graph construction synchronously.
    unsafe {
        let rc = mlx_construct_graph(
            c_ops.as_ptr(),
            c_ops.len(),
            Some(attest_trampoline),
            ctx_ptr,
        );

        if rc != 0 {
            if let Some(failed) = ctx.failed_op {
                fail!(
                    EACCES,
                    "GRAPH_OP_NOT_AUTHORISED",
                    "{failed:?} not authorised by the signed ExecutionClass"
                );
            } else {
                fail!(
                    EACCES,
                    "GRAPH_OP_NOT_AUTHORISED",
                    "operator rejected by MLX shim hook"
                );
            }
        }
    }

    Ok(())
}
