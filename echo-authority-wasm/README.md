# echo-authority-wasm

The [Echo Authority Protocol](https://moneymusk.space/protocol) Border Control verifier,
compiled to WebAssembly. It is the **same code** as
[`echo-authority-core`](https://crates.io/crates/echo-authority-core) — a second runtime,
not a second implementation — so the browser reaches the identical verdict as the native
crate and the TypeScript reference on every vector.

## Why a raw ABI (no wasm-bindgen)

Border Control only ever *verifies*; it never draws randomness, opens a socket, or reads a
clock it isn't handed. That lets the module stay tiny and dependency-light. It exposes three
`#[no_mangle]` functions over linear memory:

```
alloc(len: usize) -> *mut u8      // reserve a scratch buffer
dealloc(ptr, len)                 // free it
run(ptr, len) -> u64              // evaluate; returns (outPtr << 32) | outLen
```

`run` takes a UTF-8 `{ authority, invocation, state }` request and returns a UTF-8
`{ decision, reason, receipt }` verdict. Pack/unpack from JavaScript:

```js
const { instance } = await WebAssembly.instantiate(bytes, {})
const { memory, alloc, dealloc, run } = instance.exports

function evaluate(requestJson) {
  const enc = new TextEncoder().encode(requestJson)
  const ptr = alloc(enc.length)
  new Uint8Array(memory.buffer, ptr, enc.length).set(enc)
  const packed = run(ptr, enc.length)              // BigInt
  const outPtr = Number(packed >> 32n)
  const outLen = Number(packed & 0xffffffffn)
  const out = new TextDecoder().decode(new Uint8Array(memory.buffer, outPtr, outLen))
  dealloc(ptr, enc.length); dealloc(outPtr, outLen)
  return JSON.parse(out)
}
```

## Build

```sh
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
# -> target/wasm32-unknown-unknown/release/echo_authority_wasm.wasm  (~173 KB)
```

You can watch it run in the browser, live, at <https://moneymusk.space/protocol>.

## License

Dual-licensed under either [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE), at your option.
