//! WASM FFI boundary. No external crates; the JS side talks to these three
//! functions directly through linear memory.

pub mod engine;
pub mod http;
pub mod json;
pub mod operators;
pub mod regex;
pub mod seclang;
pub mod transforms;

/// Allocate `len` bytes, return pointer. JS writes input here.
#[no_mangle]
pub extern "C" fn waf_alloc(len: usize) -> *mut u8 {
    let mut v: Vec<u8> = Vec::with_capacity(len);
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

/// Free a buffer previously returned by waf_alloc or waf_run.
#[no_mangle]
pub extern "C" fn waf_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            drop(Vec::from_raw_parts(ptr, 0, len));
        }
    }
}

/// Run the engine. Input: length-prefixed wire format (see engine.rs).
/// Returns (ptr << 32) | len of the JSON output. Caller frees with waf_free.
#[no_mangle]
pub extern "C" fn waf_run(ptr: *const u8, len: usize) -> u64 {
    const MAX_INPUT: usize = 4 * 1024 * 1024; // 4 MiB cap
    let len = len.min(MAX_INPUT);
    let input = unsafe { std::slice::from_raw_parts(ptr, len) };
    let out = engine::run_from_wire(input);
    let mut v: Vec<u8> = Vec::with_capacity(out.len());
    v.extend_from_slice(&out);
    let p = v.as_mut_ptr();
    let l = v.len() as u64;
    std::mem::forget(v);
    ((p as u64) << 32) | l
}
