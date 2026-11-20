//! Observations via ScreenCaptureKit with pre-encoder masking (GAP-34, FS-701 §4.6.1).
//!
//! Enforces:
//! - Frame-synchronous masking of PII / secret text bounding boxes to 0.
//! - Automatic frame blur during high-velocity scrolling (`scroll_velocity > max_velocity`).
//! - Verification of macOS Screen Recording TCC consent (`kTCCServiceScreenCapture`),
//!   failing closed with `SCREEN_RECORDING_PERMISSION_REQUIRED` if permission is denied.

use enclave_core::error::EnclaveResult;
use enclave_core::fail;

use crate::classes::world::{mask_frame, Frame, Rect};

/// Check if Screen Recording permission is granted on macOS (TCC).
///
/// On macOS, dynamically queries `CGPreflightScreenCaptureAccess()` from CoreGraphics.
/// Returns `Err(SCREEN_RECORDING_PERMISSION_REQUIRED)` if access is not granted.
/// Other platforms return SCREEN_CAPTURE_UNSUPPORTED, never a consent success.
pub fn check_screen_recording_permission() -> EnclaveResult<()> {
    #[cfg(target_os = "macos")]
    unsafe {
        let path = b"/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics\0";
        let handle = libc::dlopen(path.as_ptr() as *const libc::c_char, libc::RTLD_LAZY);
        if handle.is_null() {
            fail!(EACCES, "SCREEN_RECORDING_PERMISSION_UNAVAILABLE");
        }
        let sym_name = b"CGPreflightScreenCaptureAccess\0";
        let sym = libc::dlsym(handle, sym_name.as_ptr() as *const libc::c_char);
        if sym.is_null() {
            libc::dlclose(handle);
            fail!(EACCES, "SCREEN_RECORDING_PERMISSION_UNAVAILABLE");
        }
        let preflight: extern "C" fn() -> bool = std::mem::transmute(sym);
        let granted = preflight();
        libc::dlclose(handle);
        if !granted {
            fail!(
                EACCES,
                "SCREEN_RECORDING_PERMISSION_REQUIRED",
                "Screen Recording permission not granted (grant in System Settings -> Privacy & Security -> Screen Recording)"
            );
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        fail!(ENOSYS, "SCREEN_CAPTURE_UNSUPPORTED");
    }
    #[cfg(target_os = "macos")]
    Ok(())
}

/// Screen capture observer for browser window observations.
#[derive(Debug, Clone)]
pub struct ScreenCaptureObserver {
    /// Window ID filter (0 / None captures active browser).
    pub window_id: Option<u32>,
    /// Velocity threshold above which the frame is blurred (default 2000.0 px/s).
    pub max_velocity: f32,
}

impl Default for ScreenCaptureObserver {
    fn default() -> Self {
        Self {
            window_id: None,
            max_velocity: 2000.0,
        }
    }
}

impl ScreenCaptureObserver {
    /// Create a new ScreenCaptureObserver.
    pub fn new(window_id: Option<u32>) -> Self {
        Self {
            window_id,
            max_velocity: 2000.0,
        }
    }

    /// Pre-encoder masking applied to a captured frame.
    ///
    /// Union of PII bounding boxes is zeroed (0 residual bytes).
    /// If `scroll_velocity > max_velocity`, the entire frame is blurred to its mean.
    pub fn mask(
        &self,
        frame: &mut Frame,
        pii_boxes: &[Rect],
        scroll_velocity: f32,
    ) -> EnclaveResult<()> {
        mask_frame(frame, pii_boxes, scroll_velocity, self.max_velocity)
    }

    /// Check whether any residual non-zero bytes exist within the declared PII boxes.
    pub fn verify_zero_pii_residual(frame: &Frame, pii_boxes: &[Rect]) -> bool {
        if frame.validate().is_err() {
            return false;
        }
        for r in pii_boxes {
            let Ok((right, bottom)) = r.bounds(frame) else {
                return false;
            };
            for y in r.y..bottom {
                for x in r.x..right {
                    if frame.px[y * frame.w + x] != 0 {
                        return false;
                    }
                }
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pre_encoder_masking_zeroes_pii_boxes() {
        let observer = ScreenCaptureObserver::default();
        let mut frame = Frame {
            w: 16,
            h: 16,
            px: vec![255; 256],
        };
        let pii_boxes = vec![
            Rect {
                x: 2,
                y: 2,
                w: 4,
                h: 4,
            },
            Rect {
                x: 10,
                y: 8,
                w: 3,
                h: 5,
            },
        ];

        assert!(!ScreenCaptureObserver::verify_zero_pii_residual(
            &frame, &pii_boxes
        ));

        observer.mask(&mut frame, &pii_boxes, 0.0).unwrap();

        assert!(ScreenCaptureObserver::verify_zero_pii_residual(
            &frame, &pii_boxes
        ));
        // Check unmasked region is preserved
        assert_eq!(frame.px[0], 255);
        assert_eq!(frame.px[15], 255);
    }

    #[test]
    fn test_high_velocity_scroll_blurs_frame() {
        let observer = ScreenCaptureObserver::default();
        let mut frame = Frame {
            w: 4,
            h: 2,
            px: vec![0, 50, 100, 150, 200, 250, 25, 75],
        };
        let expected_mean =
            (frame.px.iter().map(|p| *p as u64).sum::<u64>() / frame.px.len() as u64) as u8;

        observer.mask(&mut frame, &[], 3500.0).unwrap();

        assert!(frame.px.iter().all(|&p| p == expected_mean));
    }
}
