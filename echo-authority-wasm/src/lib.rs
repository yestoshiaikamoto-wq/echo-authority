//! echo-authority-wasm — the reference Border Control verifier, compiled to WebAssembly.
//!
//! This is the SAME `echo-authority-core` logic, running in the browser. It exposes a tiny raw
//! ABI (no wasm-bindgen, no glue framework):
//!
//!   * `alloc(len) -> ptr`         reserve `len` bytes of linear memory for the request string
//!   * `dealloc(ptr, len)`         free a buffer
//!   * `run(ptr, len) -> u64`      evaluate the request; returns (out_ptr << 32) | out_len
//!
//! The host writes a UTF-8 `{ authority, invocation, state }` document at `ptr`, calls `run`,
//! then reads `out_len` bytes at `out_ptr` — the canonical verdict JSON. Because this is the
//! same verifier as the CLI and the TypeScript reference, it returns the identical verdict.

use echo_authority_core::evaluate_json;

// wasm32-unknown-unknown has no OS entropy. Border Control never asks for randomness on the
// verify path, but getrandom must link, so we register a stub. If it is ever reached, that is
// a bug, not a silent weak key — verification does not consume it.
getrandom::register_custom_getrandom!(unused_entropy);
fn unused_entropy(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    for b in buf.iter_mut() {
        *b = 0;
    }
    Ok(())
}

/// Reserve `len` bytes and hand the host a pointer into linear memory.
#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut buf: Vec<u8> = Vec::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Free a buffer previously handed out by `alloc` (or returned by `run`).
///
/// # Safety
/// `ptr`/`len` must originate from this module's allocator.
#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        drop(Vec::from_raw_parts(ptr, 0, len));
    }
}

/// Evaluate a request document at `ptr`/`len`. Returns `(out_ptr << 32) | out_len` where the
/// host reads `out_len` bytes at `out_ptr` for the verdict JSON.
///
/// # Safety
/// `ptr`/`len` must describe a valid UTF-8 buffer in this module's linear memory.
#[no_mangle]
pub unsafe extern "C" fn run(ptr: *const u8, len: usize) -> u64 {
    let input = std::slice::from_raw_parts(ptr, len);
    let s = std::str::from_utf8(input).unwrap_or("");
    let verdict = evaluate_json(s).json.into_bytes();
    let out_len = verdict.len() as u64;
    let mut boxed = verdict.into_boxed_slice();
    let out_ptr = boxed.as_mut_ptr() as u64;
    std::mem::forget(boxed);
    (out_ptr << 32) | out_len
}
