//! Reference fixture vocabulary over caller-declared names. No CoreML model
//! is parsed, compiled or executed here; unknown names and embedded NULs fail closed.

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};

use crate::topology::{OpAttestor, OpFamily};

/// Actual closed-graph CPU CoreML backend; reference vocabulary helpers below
/// remain separate fixtures and are not used to admit framework programs.
pub mod runtime;

/// Fixed trained BERT debug component; not wired to production class admission.
pub mod bert;

extern "C" {
    fn mil_inspect_operations(
        op_names: *const *const c_char,
        count: libc::size_t,
        hook: Option<extern "C" fn(c_int, *mut c_void) -> c_int>,
        context: *mut c_void,
    ) -> c_int;
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

struct MilContext<'a> {
    attest: &'a mut OpAttestor,
    failed_op: Option<OpFamily>,
}

extern "C" fn mil_admit_trampoline(op_raw: c_int, ctx_ptr: *mut c_void) -> c_int {
    if ctx_ptr.is_null() {
        return -1;
    }
    // SAFETY: ctx_ptr is exclusively borrowed by the enclosing inspect_and_admit call.
    let ctx = unsafe { &mut *(ctx_ptr as *mut MilContext<'_>) };
    let op = match from_c_int(op_raw) {
        Some(o) => o,
        None => return -2, // Unknown families must never be silently skipped
    };
    if let Err(_e) = ctx.attest.admit(op) {
        ctx.failed_op = Some(op);
        return -3; // Denied by OpAttestor
    }
    0 // Admitted
}

/// Validate names from the explicit reference fixture vocabulary.
/// Faults fail-closed with `GRAPH_OP_NOT_AUTHORISED` if any operator family
/// is not authorized by the signed [`crate::manifest::ExecutionClass`].
pub fn inspect_and_admit(attest: &mut OpAttestor, mil_ops: &[&str]) -> EnclaveResult<()> {
    let c_strings: Vec<CString> = mil_ops
        .iter()
        .map(|s| CString::new(*s).map_err(|_| err!(EINVAL, "MIL_OPERATOR_NUL")))
        .collect::<EnclaveResult<_>>()?;
    let c_ptrs: Vec<*const c_char> = c_strings.iter().map(|cs| cs.as_ptr()).collect();

    let mut ctx = MilContext {
        attest,
        failed_op: None,
    };
    let ctx_ptr = &mut ctx as *mut _ as *mut c_void;

    // SAFETY: Calling C FFI with valid pointers for the duration of the call.
    unsafe {
        let rc = mil_inspect_operations(
            c_ptrs.as_ptr(),
            c_ptrs.len(),
            Some(mil_admit_trampoline),
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
                    "MIL operator rejected during pre-compile inspection"
                );
            }
        }
    }

    Ok(())
}
