use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};

fn cli(args: &[&str], input: Option<&Value>) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_echo-authority-cli"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(value) = input {
        child.stdin.take().unwrap().write_all(value.to_string().as_bytes()).unwrap();
    } else {
        drop(child.stdin.take());
    }
    child.wait_with_output().unwrap()
}

#[test]
fn generated_seed_and_public_key_keep_the_existing_output_contract() {
    let first = cli(&["keygen"], None);
    let second = cli(&["keygen"], None);
    assert!(first.status.success() && second.status.success());
    assert_ne!(first.stdout, second.stdout);
    let generated: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(generated.as_object().unwrap().len(), 2);
    let seed = generated["seed_hex"].as_str().unwrap();
    assert_eq!(seed.len(), 64);
    assert_eq!(hex::decode(seed).unwrap().len(), 32);
    // The explicit-seed path must retain the encoding expected by existing callers.
    let explicit = cli(&["keygen", "--from", seed], None);
    assert!(explicit.status.success());
    assert_eq!(explicit.stdout, first.stdout);
    assert_eq!(generated["public_b64"].as_str().unwrap().len(), 44);
}

#[test]
fn invalid_fixture_input_emits_no_key() {
    for args in [vec!["keygen", "--from"], vec!["keygen", "--from", ""],
        vec!["keygen", "--from", "not-hex"], vec!["keygen", "--from", "7"]] {
        let output = cli(&args, None);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn mint_and_invoke_still_reproduce_the_legacy_signed_vector() {
    let output = Command::new(env!("CARGO_BIN_EXE_dump-vectors")).output().unwrap();
    assert!(output.status.success());
    let vectors: Value = serde_json::from_slice(&output.stdout).unwrap();
    let request = &vectors[0]["request"];
    for (command, field, seed) in [("mint", "authority", "07".repeat(32)),
        ("invoke", "invocation", "09".repeat(32))] {
        let signed = cli(&[command, "--seed", &seed], Some(&request[field]));
        assert!(signed.status.success(), "{}", String::from_utf8_lossy(&signed.stderr));
        assert_eq!(serde_json::from_slice::<Value>(&signed.stdout).unwrap(), request[field]);
    }
}
