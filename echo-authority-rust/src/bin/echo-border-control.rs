//! echo-border-control — a tiny CLI wrapper around the deterministic verifier.
//!
//! Reads one JSON document on stdin of the form:
//!   { "authority": {...}, "invocation": {...}, "state": {...} }
//! and prints the verdict as JSON:
//!   { "decision": "ALLOW" | "DENY", "reason": "OK" | ..., "receipt": "<hex>" | null }
//!
//! Exit code is 0 on ALLOW, 1 on DENY, 2 on malformed input — so it composes in a shell:
//!   cat request.json | echo-border-control && do_the_thing
//!
//! It calls `echo_authority_core::evaluate_json`, the exact same entry point the WebAssembly
//! build exposes to the browser. CLI, browser, and any embedder run identical logic.

use echo_authority_core::evaluate_json;
use std::io::Read;

fn main() {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        eprintln!("could not read stdin");
        std::process::exit(2);
    }

    let verdict = evaluate_json(&input);
    println!("{}", verdict.json);
    std::process::exit(if verdict.allow { 0 } else { 1 });
}
