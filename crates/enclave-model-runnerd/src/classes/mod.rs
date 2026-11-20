//! The six post-autoregressive class gates (FS-701 §4) plus the `AR_CAUSAL`
//! baseline. Each gate wraps a backend trait; the reference CPU backends load
//! their weights from the admitted `.safetensors` mapping.

pub mod ar;
pub mod byte_concept;
pub mod diffusion;
pub mod rlcd;
pub mod speculative;
pub mod ssm;
pub mod world;
