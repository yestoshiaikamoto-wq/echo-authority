//! echo-authority-cli — mint, sign, invoke, verify, and attenuate Authority Objects.
//!
//! A developer + auditor tool. Every subcommand reads/writes canonical JSON on stdin/stdout,
//! so it composes with `echo-border-control` and with any other implementation of the protocol.
//! Signatures are real Ed25519. Keys are 32-byte seeds, hex-encoded — keep the secret seed safe.
//!
//! SUBCOMMANDS
//!   keygen                       -> {"seed_hex","public_b64"}                (stdin: none)
//!   mint       --seed <hex>      -> a signed AuthorityObject                 (stdin: authority fields JSON)
//!   invoke     --seed <hex>      -> a signed Invocation                      (stdin: invocation fields JSON)
//!   verify                       -> {"decision","reason","receipt"} exit 0/1 (stdin: {authority,invocation,state})
//!   attenuate                    -> {"ok","violations"}          exit 0/1    (stdin: {child,parent})
//!
//! The point: anyone can produce their OWN signed vectors and check them against either
//! implementation (this CLI, or echo-authority-wasm in the browser). Two implementations,
//! one verdict — provable from your own terminal.

use echo_authority_core::{
    canonical_authority, canonical_invocation, check_attenuation, evaluate_json, AuthorityObject,
    Invocation,
};
use ed25519_dalek::{Signer, SigningKey};
use std::io::Read;

fn b64(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        out.push(A[(b[0] >> 2) as usize] as char);
        out.push(A[(((b[0] & 0x03) << 4) | (b[1] >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 { A[(((b[1] & 0x0f) << 2) | (b[2] >> 6)) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { A[(b[2] & 0x3f) as usize] as char } else { '=' });
    }
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

/// Deterministic key from a 32-byte hex seed.
fn key_from_seed(seed_hex: &str) -> Result<SigningKey, String> {
    let bytes = hex_decode(seed_hex).ok_or("seed is not valid hex")?;
    if bytes.len() != 32 {
        return Err(format!("seed must be 32 bytes (64 hex chars), got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&arr))
}

fn read_stdin() -> String {
    let mut buf = String::new();
    let _ = std::io::stdin().read_to_string(&mut buf);
    buf
}

/// Pull `--seed <hex>` out of the argument list.
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("");

    match cmd {
        "keygen" => {
            // A deterministic seed derived from process entropy substitute: since we avoid the
            // OS RNG for portability, accept an optional --from <hex> to expand, else use a
            // time-mixed seed. Auditors who need reproducibility pass --from.
            let seed = if let Some(from) = flag(&args, "--from") {
                hex_decode(from).unwrap_or_else(|| die("--from is not valid hex")).into_iter().cycle().take(32).collect::<Vec<u8>>()
            } else {
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                let mut s = [0u8; 32];
                let n = nanos.to_le_bytes();
                for (i, b) in s.iter_mut().enumerate() {
                    *b = n[i % n.len()] ^ (i as u8).wrapping_mul(31).wrapping_add(0x5b);
                }
                s.to_vec()
            };
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&seed[..32]);
            let k = SigningKey::from_bytes(&arr);
            println!(
                "{{\"seed_hex\":\"{}\",\"public_b64\":\"{}\"}}",
                hex_encode(&arr),
                b64(&k.verifying_key().to_bytes())
            );
        }

        "mint" => {
            let seed = flag(&args, "--seed").unwrap_or_else(|| die("mint needs --seed <hex>"));
            let key = key_from_seed(seed).unwrap_or_else(|e| die(&e));
            let input = read_stdin();
            let mut a: AuthorityObject = serde_json::from_str(&input)
                .unwrap_or_else(|e| die(&format!("could not parse authority fields: {e}")));
            a.issuer_pub = b64(&key.verifying_key().to_bytes());
            a.sig = b64(&key.sign(canonical_authority(&a).as_bytes()).to_bytes());
            println!("{}", serde_json::to_string(&a).unwrap());
        }

        "invoke" => {
            let seed = flag(&args, "--seed").unwrap_or_else(|| die("invoke needs --seed <hex>"));
            let key = key_from_seed(seed).unwrap_or_else(|e| die(&e));
            let input = read_stdin();
            let mut i: Invocation = serde_json::from_str(&input)
                .unwrap_or_else(|e| die(&format!("could not parse invocation fields: {e}")));
            i.subject_pub = b64(&key.verifying_key().to_bytes());
            i.sig = b64(&key.sign(canonical_invocation(&i).as_bytes()).to_bytes());
            println!("{}", serde_json::to_string(&i).unwrap());
        }

        "verify" => {
            let input = read_stdin();
            let verdict = evaluate_json(&input);
            println!("{}", verdict.json);
            std::process::exit(if verdict.allow { 0 } else { 1 });
        }

        "attenuate" => {
            #[derive(serde::Deserialize)]
            struct Pair {
                child: AuthorityObject,
                parent: AuthorityObject,
            }
            let input = read_stdin();
            let pair: Pair = serde_json::from_str(&input)
                .unwrap_or_else(|e| die(&format!("could not parse {{child,parent}}: {e}")));
            let r = check_attenuation(&pair.child, &pair.parent);
            let violations = r
                .violations
                .iter()
                .map(|v| format!("\"{}\"", v.replace('"', "'")))
                .collect::<Vec<_>>()
                .join(",");
            println!("{{\"ok\":{},\"violations\":[{}]}}", r.ok, violations);
            std::process::exit(if r.ok { 0 } else { 1 });
        }

        "" | "help" | "-h" | "--help" => {
            eprintln!(
                "echo-authority-cli — mint, invoke, verify, attenuate Authority Objects\n\n\
                 USAGE\n\
                 \x20 echo-authority-cli keygen [--from <hex>]\n\
                 \x20 echo-authority-cli mint     --seed <hex>   < authority-fields.json\n\
                 \x20 echo-authority-cli invoke   --seed <hex>   < invocation-fields.json\n\
                 \x20 echo-authority-cli verify                  < request.json     (exit 0=ALLOW 1=DENY)\n\
                 \x20 echo-authority-cli attenuate                < child-parent.json (exit 0=subset 1=not)\n"
            );
        }

        other => die(&format!("unknown subcommand '{other}' (try: keygen, mint, invoke, verify, attenuate)")),
    }
}
