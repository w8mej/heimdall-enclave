//! Opaque `Ref` type for labeled capability handles (FS-704 §3.2, §8.2.1).
//!
//! DEFECT-F-65: a `PlanRef` can only be built by the runtime from a heap
//! envelope whose MAC verifies ([`PlanRef::from_heap`]). Its label is copied
//! from that envelope; a plan (model-authored) can neither construct a `Ref`
//! nor choose its confidentiality or taint.

use allocative::Allocative;
use enclave_core::error::EnclaveResult;
use enclave_core::label::Label;
use starlark::any::ProvidesStaticType;
use starlark::starlark_simple_value;
use starlark::values::{starlark_value, NoSerialize, StarlarkValue};
use std::fmt;

use crate::heap::CapabilityHeap;

/// Opaque reference to an IFC capability handle in the agent runtime heap.
#[derive(Debug, Clone, PartialEq, Eq, ProvidesStaticType, Allocative, NoSerialize)]
pub struct PlanRef {
    /// Opaque handle name (e.g. `$paste_0`, `$v_1`).
    handle: String,
    /// Label copied from the MAC-verified heap envelope.
    #[allocative(skip)]
    label: Label,
}

impl PlanRef {
    /// Build a reference from a live heap value. The envelope MAC is verified
    /// (`HANDLE_FORGERY` for unknown, wiped or tampered handles) and the label
    /// is the envelope's, never a caller-supplied one.
    pub fn from_heap(heap: &CapabilityHeap, handle: &str) -> EnclaveResult<Self> {
        let value = heap.get(handle)?;
        Ok(Self {
            handle: value.envelope.handle.clone(),
            label: value.envelope.label,
        })
    }

    /// The heap handle this reference names.
    pub fn handle(&self) -> &str {
        &self.handle
    }

    /// The heap label (MAC-protected in the envelope).
    pub fn label(&self) -> Label {
        self.label
    }
}

impl fmt::Display for PlanRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Ref({}, {:?}, {:?})",
            self.handle, self.label.c, self.label.t
        )
    }
}

starlark_simple_value!(PlanRef);

#[starlark_value(type = "Ref")]
impl<'v> StarlarkValue<'v> for PlanRef {}
