//! Current Rust scratch for the existing debug-only MLX pipe protocol.
//!
//! Borrowed source bytes, public result copies, Python/framework/kernel state,
//! allocator history and physical erasure remain separate ownership boundaries.

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};

/// Immediately adopt the decoder's successful allocation before later checks,
/// configuration, child creation or IO can fail. No payload copy or Vec escape.
pub(super) fn with_weights<R>(
    weights: Vec<f32>,
    operation: impl FnOnce(&[f32]) -> EnclaveResult<R>,
) -> EnclaveResult<R> {
    let weights = crate::arena::FloatScratch::new(weights, "mlx-load-weights");
    operation(&weights)
}

struct LoadFrame {
    bytes: Vec<u8>,
    #[cfg(test)]
    allocation: (usize, usize),
}

impl Drop for LoadFrame {
    fn drop(&mut self) {
        for byte in &mut self.bytes {
            // SAFETY: live initialized byte, exclusively owned until Drop ends.
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        tests::observe(
            "load-frame",
            &self.bytes,
            self.allocation == (self.bytes.as_ptr() as usize, self.bytes.capacity()),
        );
    }
}

/// Serialize into one fully initialized fixed allocation guarded before private
/// writes. Slice-only synchronous access cannot grow, extract or retain it.
pub(super) fn with_load_frame<R>(
    weights: &[f32],
    transfer: impl FnOnce(&[u8]) -> EnclaveResult<R>,
) -> EnclaveResult<R> {
    let bytes = vec![0; weights.len() * 4];
    let mut frame = LoadFrame {
        #[cfg(test)]
        allocation: (bytes.as_ptr() as usize, bytes.capacity()),
        bytes,
    };
    for (chunk, value) in frame.bytes.chunks_exact_mut(4).zip(weights) {
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    transfer(&frame.bytes)
}

struct ByteScratch<'a, const N: usize> {
    bytes: &'a mut [u8; N],
    #[cfg(test)]
    owner: &'static str,
}

impl<'a, const N: usize> ByteScratch<'a, N> {
    fn new(bytes: &'a mut [u8; N], _owner: &'static str) -> Self {
        Self {
            bytes,
            #[cfg(test)]
            owner: _owner,
        }
    }
}

impl<const N: usize> Drop for ByteScratch<'_, N> {
    fn drop(&mut self) {
        for byte in self.bytes.iter_mut() {
            // SAFETY: the exclusive borrow keeps original initialized storage
            // live; the guard moves only the borrow, not private array bytes.
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        tests::observe(self.owner, self.bytes, true);
    }
}

pub(super) fn read_ready(
    receive: impl FnOnce(&mut [u8; 4]) -> EnclaveResult<()>,
) -> EnclaveResult<()> {
    let mut bytes = [0; 4];
    let ready = ByteScratch::new(&mut bytes, "ready");
    receive(ready.bytes)?;
    if ready.bytes.as_slice() != b"MLX1" {
        fail!(EIO, "MLX_WORKER_PROTOCOL");
    }
    Ok(())
}

pub(super) fn send_request(
    prefix: &[u8],
    send: impl FnOnce(&[u8]) -> EnclaveResult<()>,
) -> EnclaveResult<()> {
    let mut bytes = [0; 1];
    let request = ByteScratch::new(&mut bytes, "request");
    request.bytes[0] = *prefix.last().unwrap_or(&b'\n');
    send(request.bytes)
}

struct OutputScratch<'a> {
    values: &'a mut [f32; 256],
}

impl Drop for OutputScratch<'_> {
    fn drop(&mut self) {
        for value in self.values.iter_mut() {
            // SAFETY: initialized float in original live exclusively borrowed
            // output storage, retained until the synchronous decode completes.
            unsafe {
                std::ptr::write_volatile(value, 0.0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        tests::observe_output(self.values);
    }
}

pub(super) fn read_logits(
    receive: impl FnOnce(&mut [u8; 1024]) -> EnclaveResult<()>,
) -> EnclaveResult<[f32; 256]> {
    let mut bytes = [0; 1024];
    let raw = ByteScratch::new(&mut bytes, "reply");
    receive(raw.bytes)?;
    let mut values = [0.0; 256];
    let output = OutputScratch {
        values: &mut values,
    };
    for (value, bytes) in output.values.iter_mut().zip(raw.bytes.chunks_exact(4)) {
        *value = f32::from_le_bytes(bytes.try_into().map_err(|_| err!(EIO, "MLX_RESULT_SIZE"))?);
    }
    if output.values.iter().any(|value| !value.is_finite()) {
        fail!(EIO, "MLX_RESULT_NONFINITE");
    }
    // The existing public API transfers a by-value array to its caller. Wipe
    // the private source array and raw reply before returning that public copy.
    let returned = *output.values;
    drop(output);
    drop(raw);
    Ok(returned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arena::float_scratch_tests::{self, Event};
    use std::cell::RefCell;

    #[derive(Debug, PartialEq, Eq)]
    struct Observation {
        owner: &'static str,
        initialized: usize,
        zero: bool,
        allocation_unchanged: bool,
    }
    thread_local! {
        static EVENTS: RefCell<Option<Vec<Observation>>> = const { RefCell::new(None) };
    }
    pub(super) fn observe(owner: &'static str, bytes: &[u8], allocation_unchanged: bool) {
        EVENTS.with(|events| {
            if let Some(events) = events.borrow_mut().as_mut() {
                events.push(Observation {
                    owner,
                    initialized: bytes.len(),
                    zero: bytes.iter().all(|byte| *byte == 0),
                    allocation_unchanged,
                });
            }
        });
    }
    pub(super) fn observe_output(values: &[f32; 256]) {
        EVENTS.with(|events| {
            if let Some(events) = events.borrow_mut().as_mut() {
                events.push(Observation {
                    owner: "output",
                    initialized: values.len(),
                    zero: values.iter().all(|value| value.to_bits() == 0),
                    allocation_unchanged: true,
                });
            }
        });
    }
    fn begin() {
        EVENTS.with(|events| *events.borrow_mut() = Some(Vec::new()));
        float_scratch_tests::begin();
    }
    fn finish() -> (Vec<Observation>, Vec<Event>) {
        (
            EVENTS.with(|events| events.borrow_mut().take().unwrap()),
            float_scratch_tests::finish(),
        )
    }
    fn zero(owner: &'static str, initialized: usize) -> Observation {
        Observation {
            owner,
            initialized,
            zero: true,
            allocation_unchanged: true,
        }
    }
    fn weight_event(length: usize) -> Vec<Event> {
        vec![Event::Scrubbed("mlx-load-weights", length, true)]
    }
    fn write_reply(raw: &mut [u8; 1024], values: &[f32; 256]) {
        for (chunk, value) in raw.chunks_exact_mut(4).zip(values) {
            chunk.copy_from_slice(&value.to_le_bytes());
        }
    }

    #[test]
    fn mlx_owner_full_load_frame_preserves_all_65536_values_and_scrubs() {
        let weights: Vec<f32> = (0..65536)
            .map(|index| index as f32 / 8.0 - 4096.0)
            .collect();
        let reference = weights.clone();
        begin();
        with_weights(weights, |weights| {
            with_load_frame(weights, |raw| {
                assert_eq!(raw.len(), 262144);
                for (index, (bytes, value)) in raw.chunks_exact(4).zip(&reference).enumerate() {
                    assert_eq!(bytes, value.to_le_bytes(), "wire element{index}");
                }
                read_ready(|ready| {
                    *ready = *b"MLX1";
                    Ok(())
                })
            })
        })
        .unwrap();
        assert_eq!(
            finish(),
            (
                vec![zero("ready", 4), zero("load-frame", 262144)],
                weight_event(65536)
            )
        );
    }

    #[test]
    fn mlx_owner_pre_frame_refusal_scrubs_original_weights_and_preserves_error() {
        begin();
        let error = with_weights(vec![11.5; 65536], |_| -> EnclaveResult<()> {
            Err(err!(ENOSYS, "MLX_RUNTIME_NOT_CONFIGURED"))
        })
        .unwrap_err();
        assert!(error.is("MLX_RUNTIME_NOT_CONFIGURED"));
        assert_eq!(finish(), (Vec::new(), weight_event(65536)));
    }

    #[test]
    fn mlx_owner_send_and_partial_or_bad_ready_refusals_scrub_load_owners() {
        for mode in 0..3 {
            begin();
            let error = with_weights(vec![3.5; 65536], |weights| {
                with_load_frame(weights, |raw| {
                    assert_eq!(&raw[..4], &3.5f32.to_le_bytes());
                    if mode == 0 {
                        return Err(err!(EIO, "MLX_WRITE_FAILED"));
                    }
                    read_ready(|ready| {
                        ready[..2].copy_from_slice(b"NO");
                        if mode == 1 {
                            return Err(err!(EIO, "MLX_READ_CLOSED"));
                        }
                        ready[2..].copy_from_slice(b"PE");
                        Ok(())
                    })
                })
            })
            .unwrap_err();
            assert!(error.is(match mode {
                0 => "MLX_WRITE_FAILED",
                1 => "MLX_READ_CLOSED",
                _ => "MLX_WORKER_PROTOCOL",
            }));
            let expected = if mode == 0 {
                vec![zero("load-frame", 262144)]
            } else {
                vec![zero("ready", 4), zero("load-frame", 262144)]
            };
            assert_eq!(finish(), (expected, weight_event(65536)));
        }
    }

    #[test]
    fn mlx_owner_finite_logits_transfer_exact_result_after_private_arrays_scrub() {
        let expected = std::array::from_fn(|index| index as f32 / 16.0 - 8.0);
        begin();
        let result = read_logits(|raw| {
            write_reply(raw, &expected);
            Ok(())
        })
        .unwrap();
        assert_eq!(result, expected);
        assert_eq!(
            finish(),
            (vec![zero("output", 256), zero("reply", 1024)], Vec::new())
        );
        assert_eq!(result[255], 7.9375);
    }

    #[test]
    fn mlx_owner_partial_reply_error_scrubs_initialized_reply_before_return() {
        begin();
        let error = read_logits(|raw| {
            raw[..37].fill(0x5a);
            Err(err!(EIO, "MLX_READ_CLOSED"))
        })
        .unwrap_err();
        assert!(error.is("MLX_READ_CLOSED"));
        assert_eq!(finish(), (vec![zero("reply", 1024)], Vec::new()));
    }

    #[test]
    fn mlx_owner_nonfinite_logits_refuse_and_scrub_raw_and_private_output() {
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            begin();
            let error = read_logits(|raw| {
                let mut values = [3.25; 256];
                values[137] = value;
                write_reply(raw, &values);
                Ok(())
            })
            .unwrap_err();
            assert!(error.is("MLX_RESULT_NONFINITE"));
            assert_eq!(
                finish(),
                (vec![zero("output", 256), zero("reply", 1024)], Vec::new())
            );
        }
    }

    #[test]
    fn mlx_owner_request_preserves_empty_and_last_byte_and_scrubs_on_send_error() {
        for (prefix, expected) in [(b"".as_slice(), b'\n'), (b"private-prefix", b'x')] {
            begin();
            let error = send_request(prefix, |request| {
                assert_eq!(request, &[expected]);
                Err(err!(EIO, "MLX_WRITE_FAILED"))
            })
            .unwrap_err();
            assert!(error.is("MLX_WRITE_FAILED"));
            assert_eq!(finish(), (vec![zero("request", 1)], Vec::new()));
        }
    }

    #[test]
    fn mlx_owner_unwind_retains_cleanup_for_load_frame_and_partial_reply() {
        begin();
        let result = std::panic::catch_unwind(|| {
            let _: EnclaveResult<()> = with_weights(vec![6.25; 65536], |weights| {
                with_load_frame(weights, |raw| {
                    assert_eq!(&raw[..4], &6.25f32.to_le_bytes());
                    let _ = read_logits(|reply| -> EnclaveResult<()> {
                        reply[..37].fill(0x7b);
                        panic!("synthetic owned writer panic");
                    });
                    Ok(())
                })
            });
        });
        assert!(result.is_err());
        assert_eq!(
            finish(),
            (
                vec![zero("reply", 1024), zero("load-frame", 262144)],
                weight_event(65536)
            )
        );
    }
}
