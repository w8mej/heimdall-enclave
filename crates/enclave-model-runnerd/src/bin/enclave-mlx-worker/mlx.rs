//! Minimal safe wrapper over the libmlxc functions this worker uses.
//!
//! Every MLX failure ends the process (see `on_mlx_error`); the runner treats
//! a closed pipe as a revoked worker, so no partial result is ever returned.

use std::os::raw::{c_char, c_int, c_void};

/// Exit code for any MLX error.
pub const EXIT_MLX_ERROR: i32 = 6;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Handle {
    ctx: *mut c_void,
}

impl Handle {
    const NULL: Handle = Handle {
        ctx: std::ptr::null_mut(),
    };
}

#[repr(C)]
#[derive(Clone, Copy)]
struct OptionalInt {
    value: c_int,
    has_value: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct OptionalFloat {
    value: f32,
    has_value: bool,
}

/// MLX element types used here (`mlx_dtype` enum order).
#[derive(Clone, Copy)]
#[repr(C)]
pub enum Dtype {
    Uint32 = 3,
    Float32 = 10,
    Bfloat16 = 12,
}

#[link(name = "mlxc")]
extern "C" {
    fn mlx_array_new() -> Handle;
    fn mlx_array_new_data(
        data: *const c_void,
        shape: *const c_int,
        dim: c_int,
        dtype: c_int,
    ) -> Handle;
    fn mlx_array_free(array: Handle) -> c_int;
    fn mlx_array_eval(array: Handle) -> c_int;
    fn mlx_array_size(array: Handle) -> usize;
    fn mlx_array_data_float32(array: Handle) -> *const f32;
    fn mlx_matmul(res: *mut Handle, a: Handle, b: Handle, s: Handle) -> c_int;
    fn mlx_add(res: *mut Handle, a: Handle, b: Handle, s: Handle) -> c_int;
    fn mlx_multiply(res: *mut Handle, a: Handle, b: Handle, s: Handle) -> c_int;
    fn mlx_sigmoid(res: *mut Handle, a: Handle, s: Handle) -> c_int;
    fn mlx_subtract(res: *mut Handle, a: Handle, b: Handle, s: Handle) -> c_int;
    fn mlx_divide(res: *mut Handle, a: Handle, b: Handle, s: Handle) -> c_int;
    fn mlx_maximum(res: *mut Handle, a: Handle, b: Handle, s: Handle) -> c_int;
    fn mlx_tanh(res: *mut Handle, a: Handle, s: Handle) -> c_int;
    fn mlx_erf(res: *mut Handle, a: Handle, s: Handle) -> c_int;
    fn mlx_exp(res: *mut Handle, a: Handle, s: Handle) -> c_int;
    fn mlx_sqrt(res: *mut Handle, a: Handle, s: Handle) -> c_int;
    fn mlx_square(res: *mut Handle, a: Handle, s: Handle) -> c_int;
    fn mlx_sum_axis(res: *mut Handle, a: Handle, axis: c_int, keepdims: bool, s: Handle) -> c_int;
    fn mlx_fast_layer_norm(
        res: *mut Handle,
        x: Handle,
        weight: Handle,
        bias: Handle,
        eps: f32,
        s: Handle,
    ) -> c_int;
    fn mlx_array_new_float(value: f32) -> Handle;
    fn mlx_array_data_uint32(array: Handle) -> *const u32;
    fn mlx_argmax_axis(
        res: *mut Handle,
        a: Handle,
        axis: c_int,
        keepdims: bool,
        s: Handle,
    ) -> c_int;
    fn mlx_slice(
        res: *mut Handle,
        a: Handle,
        start: *const c_int,
        start_num: usize,
        stop: *const c_int,
        stop_num: usize,
        strides: *const c_int,
        strides_num: usize,
        s: Handle,
    ) -> c_int;
    fn mlx_astype(res: *mut Handle, a: Handle, dtype: c_int, s: Handle) -> c_int;
    fn mlx_transpose(res: *mut Handle, a: Handle, s: Handle) -> c_int;
    fn mlx_reshape(res: *mut Handle, a: Handle, shape: *const c_int, n: usize, s: Handle) -> c_int;
    fn mlx_transpose_axes(
        res: *mut Handle,
        a: Handle,
        axes: *const c_int,
        n: usize,
        s: Handle,
    ) -> c_int;
    fn mlx_take_axis(res: *mut Handle, a: Handle, indices: Handle, axis: c_int, s: Handle)
        -> c_int;
    fn mlx_fast_rms_norm(res: *mut Handle, x: Handle, weight: Handle, eps: f32, s: Handle)
        -> c_int;
    fn mlx_fast_rope(
        res: *mut Handle,
        x: Handle,
        dims: c_int,
        traditional: bool,
        base: OptionalFloat,
        scale: f32,
        offset: c_int,
        freqs: Handle,
        s: Handle,
    ) -> c_int;
    fn mlx_fast_scaled_dot_product_attention(
        res: *mut Handle,
        q: Handle,
        k: Handle,
        v: Handle,
        scale: f32,
        mask_mode: *const c_char,
        mask: Handle,
        sinks: Handle,
        force_fused: bool,
        s: Handle,
    ) -> c_int;
    fn mlx_quantized_matmul(
        res: *mut Handle,
        x: Handle,
        w: Handle,
        scales: Handle,
        biases: Handle,
        transpose: bool,
        group_size: OptionalInt,
        bits: OptionalInt,
        mode: *const c_char,
        s: Handle,
    ) -> c_int;
    fn mlx_default_cpu_stream_new() -> Handle;
    fn mlx_default_gpu_stream_new() -> Handle;
    fn mlx_metal_is_available(res: *mut bool) -> c_int;
    fn mlx_stream_free(stream: Handle) -> c_int;
    fn mlx_set_error_handler(
        handler: Option<extern "C" fn(*const c_char, *mut c_void)>,
        data: *mut c_void,
        dtor: Option<extern "C" fn(*mut c_void)>,
    );
}

extern "C" fn on_mlx_error(_message: *const c_char, _data: *mut c_void) {
    std::process::exit(EXIT_MLX_ERROR);
}

/// Route every MLX error to process exit. Call once before any MLX use.
pub fn install_error_handler() {
    // SAFETY: registers a static handler with no data or destructor.
    unsafe { mlx_set_error_handler(Some(on_mlx_error), std::ptr::null_mut(), None) };
}

fn check(status: c_int) {
    if status != 0 {
        std::process::exit(EXIT_MLX_ERROR);
    }
}

/// The default CPU stream, freed on drop.
pub struct Stream(Handle);

impl Stream {
    pub fn cpu() -> Self {
        // SAFETY: creates a new stream handle owned by this value.
        Self(unsafe { mlx_default_cpu_stream_new() })
    }

    /// The default GPU (Metal) stream; exits with an MLX error when Metal
    /// is unavailable rather than silently computing elsewhere.
    pub fn gpu() -> Self {
        let mut available = false;
        // SAFETY: writes one bool through a valid pointer.
        check(unsafe { mlx_metal_is_available(&mut available) });
        if !available {
            std::process::exit(EXIT_MLX_ERROR);
        }
        // SAFETY: creates a new stream handle owned by this value.
        Self(unsafe { mlx_default_gpu_stream_new() })
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        // SAFETY: owned live stream handle.
        unsafe { mlx_stream_free(self.0) };
    }
}

/// An owned MLX array, freed on drop.
pub struct Array(Handle);

macro_rules! op {
    ($stream:expr, |$res:ident| $call:expr) => {{
        // SAFETY: inputs are live owned arrays; the result slot starts empty
        // and is owned by the returned Array.
        let mut $res = unsafe { mlx_array_new() };
        check(unsafe { $call });
        Array($res)
    }};
}

impl Array {
    /// Copy `data` (raw little-endian elements of `dtype`) into a new array.
    pub fn from_raw(data: &[u8], shape: &[i32], dtype: Dtype) -> Self {
        // SAFETY: caller supplies product(shape) elements of `dtype`; MLX copies.
        Self(unsafe {
            mlx_array_new_data(
                data.as_ptr().cast(),
                shape.as_ptr(),
                shape.len() as c_int,
                dtype as c_int,
            )
        })
    }
    pub fn from_f32(values: &[f32], shape: &[i32]) -> Self {
        // SAFETY: `values` holds product(shape) initialized f32s; MLX copies.
        Self(unsafe {
            mlx_array_new_data(
                values.as_ptr().cast(),
                shape.as_ptr(),
                shape.len() as c_int,
                Dtype::Float32 as c_int,
            )
        })
    }
    pub fn from_u32(values: &[u32], shape: &[i32]) -> Self {
        // SAFETY: `values` holds product(shape) initialized u32s; MLX copies.
        Self(unsafe {
            mlx_array_new_data(
                values.as_ptr().cast(),
                shape.as_ptr(),
                shape.len() as c_int,
                Dtype::Uint32 as c_int,
            )
        })
    }
    pub fn matmul(&self, b: &Array, s: &Stream) -> Array {
        op!(s, |r| mlx_matmul(&mut r, self.0, b.0, s.0))
    }
    /// `self @ dequantize(w, scales, biases)^T` for an affine-quantized
    /// `w` (`[out, in * bits / 32]` uint32) with `group` inputs per scale.
    pub fn quantized_matmul(
        &self,
        w: &Array,
        scales: &Array,
        biases: &Array,
        group: i32,
        bits: i32,
        s: &Stream,
    ) -> Array {
        let (group, bits) = (
            OptionalInt {
                value: group,
                has_value: true,
            },
            OptionalInt {
                value: bits,
                has_value: true,
            },
        );
        let mode = b"affine\0";
        op!(s, |r| mlx_quantized_matmul(
            &mut r,
            self.0,
            w.0,
            scales.0,
            biases.0,
            true,
            group,
            bits,
            mode.as_ptr().cast(),
            s.0
        ))
    }
    pub fn add(&self, b: &Array, s: &Stream) -> Array {
        op!(s, |r| mlx_add(&mut r, self.0, b.0, s.0))
    }
    pub fn multiply(&self, b: &Array, s: &Stream) -> Array {
        op!(s, |r| mlx_multiply(&mut r, self.0, b.0, s.0))
    }
    pub fn sigmoid(&self, s: &Stream) -> Array {
        op!(s, |r| mlx_sigmoid(&mut r, self.0, s.0))
    }
    pub fn subtract(&self, b: &Array, s: &Stream) -> Array {
        op!(s, |r| mlx_subtract(&mut r, self.0, b.0, s.0))
    }
    pub fn divide(&self, b: &Array, s: &Stream) -> Array {
        op!(s, |r| mlx_divide(&mut r, self.0, b.0, s.0))
    }
    pub fn maximum(&self, b: &Array, s: &Stream) -> Array {
        op!(s, |r| mlx_maximum(&mut r, self.0, b.0, s.0))
    }
    pub fn tanh(&self, s: &Stream) -> Array {
        op!(s, |r| mlx_tanh(&mut r, self.0, s.0))
    }
    pub fn erf(&self, s: &Stream) -> Array {
        op!(s, |r| mlx_erf(&mut r, self.0, s.0))
    }
    pub fn exp(&self, s: &Stream) -> Array {
        op!(s, |r| mlx_exp(&mut r, self.0, s.0))
    }
    pub fn sqrt(&self, s: &Stream) -> Array {
        op!(s, |r| mlx_sqrt(&mut r, self.0, s.0))
    }
    pub fn square(&self, s: &Stream) -> Array {
        op!(s, |r| mlx_square(&mut r, self.0, s.0))
    }
    /// Sum over one axis, keeping it as size 1.
    pub fn sum_keep(&self, axis: i32, s: &Stream) -> Array {
        op!(s, |r| mlx_sum_axis(&mut r, self.0, axis, true, s.0))
    }
    /// Layer norm over the last axis; `affine` = (weight, bias) or none.
    pub fn layer_norm(&self, affine: Option<(&Array, &Array)>, eps: f32, s: &Stream) -> Array {
        let (w, b) = affine.map_or((Handle::NULL, Handle::NULL), |(w, b)| (w.0, b.0));
        op!(s, |r| mlx_fast_layer_norm(&mut r, self.0, w, b, eps, s.0))
    }
    /// Index of the largest value along `axis` (uint32; ties to the lowest).
    pub fn argmax(&self, axis: i32, s: &Stream) -> Array {
        op!(s, |r| mlx_argmax_axis(&mut r, self.0, axis, false, s.0))
    }
    /// Sub-array `start..stop` per axis, unit strides.
    pub fn slice(&self, start: &[i32], stop: &[i32], s: &Stream) -> Array {
        let strides = vec![1; start.len()];
        op!(s, |r| mlx_slice(
            &mut r,
            self.0,
            start.as_ptr(),
            start.len(),
            stop.as_ptr(),
            stop.len(),
            strides.as_ptr(),
            strides.len(),
            s.0
        ))
    }
    /// Evaluate and copy out as u32 (the array must be uint32).
    pub fn to_vec_u32(&self) -> Vec<u32> {
        // SAFETY: live array; after eval, data is valid for `size` u32s.
        unsafe {
            check(mlx_array_eval(self.0));
            let data = mlx_array_data_uint32(self.0);
            if data.is_null() {
                std::process::exit(EXIT_MLX_ERROR);
            }
            std::slice::from_raw_parts(data, mlx_array_size(self.0)).to_vec()
        }
    }
    /// A float32 scalar.
    pub fn scalar(value: f32) -> Array {
        // SAFETY: creates a new owned scalar array.
        Array(unsafe { mlx_array_new_float(value) })
    }
    pub fn to_f32(&self, s: &Stream) -> Array {
        op!(s, |r| mlx_astype(
            &mut r,
            self.0,
            Dtype::Float32 as c_int,
            s.0
        ))
    }
    pub fn t(&self, s: &Stream) -> Array {
        op!(s, |r| mlx_transpose(&mut r, self.0, s.0))
    }
    pub fn reshape(&self, shape: &[i32], s: &Stream) -> Array {
        op!(s, |r| mlx_reshape(
            &mut r,
            self.0,
            shape.as_ptr(),
            shape.len(),
            s.0
        ))
    }
    pub fn permute(&self, axes: &[i32], s: &Stream) -> Array {
        op!(s, |r| mlx_transpose_axes(
            &mut r,
            self.0,
            axes.as_ptr(),
            axes.len(),
            s.0
        ))
    }
    pub fn take_rows(&self, indices: &Array, s: &Stream) -> Array {
        op!(s, |r| mlx_take_axis(&mut r, self.0, indices.0, 0, s.0))
    }
    pub fn rms_norm(&self, weight: &Array, eps: f32, s: &Stream) -> Array {
        op!(s, |r| mlx_fast_rms_norm(&mut r, self.0, weight.0, eps, s.0))
    }
    /// Non-traditional (half-rotation) RoPE over the last `dims` features.
    pub fn rope(&self, dims: i32, base: f32, offset: i32, s: &Stream) -> Array {
        let base = OptionalFloat {
            value: base,
            has_value: true,
        };
        op!(s, |r| mlx_fast_rope(
            &mut r,
            self.0,
            dims,
            false,
            base,
            1.0,
            offset,
            Handle::NULL,
            s.0
        ))
    }
    /// Causal attention; `k`/`v` may have fewer heads (grouped-query).
    pub fn causal_attention(q: &Array, k: &Array, v: &Array, scale: f32, s: &Stream) -> Array {
        let mode = b"causal\0";
        op!(s, |r| mlx_fast_scaled_dot_product_attention(
            &mut r,
            q.0,
            k.0,
            v.0,
            scale,
            mode.as_ptr().cast(),
            Handle::NULL,
            Handle::NULL,
            false,
            s.0
        ))
    }
    /// Unmasked (bidirectional) attention.
    pub fn full_attention(q: &Array, k: &Array, v: &Array, scale: f32, s: &Stream) -> Array {
        let mode = b"\0";
        op!(s, |r| mlx_fast_scaled_dot_product_attention(
            &mut r,
            q.0,
            k.0,
            v.0,
            scale,
            mode.as_ptr().cast(),
            Handle::NULL,
            Handle::NULL,
            false,
            s.0
        ))
    }
    /// Evaluate and copy out as f32 (the array must be float32).
    pub fn to_vec_f32(&self) -> Vec<f32> {
        // SAFETY: live array; after eval, data is valid for `size` f32s.
        unsafe {
            check(mlx_array_eval(self.0));
            let data = mlx_array_data_float32(self.0);
            if data.is_null() {
                std::process::exit(EXIT_MLX_ERROR);
            }
            std::slice::from_raw_parts(data, mlx_array_size(self.0)).to_vec()
        }
    }
    /// Force evaluation (used to materialize weights once at load).
    pub fn eval(&self) {
        // SAFETY: live array.
        check(unsafe { mlx_array_eval(self.0) });
    }
}

impl Drop for Array {
    fn drop(&mut self) {
        // SAFETY: each Array owns exactly one live handle.
        unsafe { mlx_array_free(self.0) };
    }
}
