//! Bounded typed argument extraction. Text resembling a handle is ordinary text.
use std::collections::BTreeMap;
use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use starlark::values::{Value, ValueLike};
use starlark::values::dict::DictRef;
use starlark::values::list::ListRef;
use starlark::values::tuple::TupleRef;
use super::ref_value::PlanRef;

pub(crate) const MAX_ARGUMENT_BYTES: usize = 64 * 1024;
const MAX_NODES: usize = 1024;

#[derive(Debug)]
pub(crate) enum Argument {
    Scalar(serde_json::Value),
    Ref(PlanRef),
    List(Vec<Argument>),
    Object(BTreeMap<String, Argument>),
}
impl Argument {
    pub(crate) fn extract(value: Value<'_>) -> EnclaveResult<Self> {
        let mut nodes = 0;
        let mut bytes = 0;
        let out = Self::walk(value, 0, &mut nodes, &mut bytes)?;
        if !matches!(out, Self::Object(_)) { fail!(EINVAL, "PLAN_ARGUMENT_OBJECT_REQUIRED"); }
        Ok(out)
    }
    fn walk(value: Value<'_>, depth: usize, nodes: &mut usize, bytes: &mut usize) -> EnclaveResult<Self> {
        *nodes += 1;
        if depth > 16 || *nodes > MAX_NODES { fail!(E2BIG, "PLAN_ARGUMENT_BOUNDS"); }
        if let Some(reference) = value.downcast_ref::<PlanRef>() { return Ok(Self::Ref(reference.clone())); }
        if let Some(dict) = DictRef::from_value(value) {
            let mut out = BTreeMap::new();
            for (key, value) in dict.iter() {
                let key = key.unpack_str().ok_or_else(|| err!(EINVAL, "PLAN_ARGUMENT_KEY"))?;
                *bytes = bytes.saturating_add(key.len());
                if *bytes > MAX_ARGUMENT_BYTES { fail!(E2BIG, "PLAN_ARGUMENT_BOUNDS"); }
                out.insert(key.to_owned(), Self::walk(value, depth + 1, nodes, bytes)?);
            }
            return Ok(Self::Object(out));
        }
        if let Some(list) = ListRef::from_value(value) {
            return list.iter().map(|v| Self::walk(v, depth + 1, nodes, bytes)).collect::<EnclaveResult<Vec<_>>>().map(Self::List);
        }
        if let Some(tuple) = TupleRef::from_value(value) {
            return tuple.iter().map(|v| Self::walk(v, depth + 1, nodes, bytes)).collect::<EnclaveResult<Vec<_>>>().map(Self::List);
        }
        // Serialize scalars only; never invoke user-defined serializers or
        // recursive serialization that could erase a nested Ref's provenance.
        if !matches!(value.get_type(), "NoneType" | "bool" | "int" | "float" | "string") {
            fail!(EINVAL, "PLAN_ARGUMENT_TYPE");
        }
        if let Some(text) = value.unpack_str() {
            *bytes = bytes.saturating_add(text.len());
            if *bytes > MAX_ARGUMENT_BYTES { fail!(E2BIG, "PLAN_ARGUMENT_BOUNDS"); }
        }
        let json = value.to_json_value().map_err(|_| err!(EINVAL, "PLAN_ARGUMENT_TYPE"))?;
        *bytes = bytes.saturating_add(serde_json::to_vec(&json).map_err(|_| err!(EINVAL, "PLAN_ARGUMENT_TYPE"))?.len());
        if *bytes > MAX_ARGUMENT_BYTES { fail!(E2BIG, "PLAN_ARGUMENT_BOUNDS"); }
        Ok(Self::Scalar(json))
    }
}
