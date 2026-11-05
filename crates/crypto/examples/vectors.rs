use openwarp_crypto as oc;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("gen") => {
            let kp = oc::Keypair::generate();
            let ct = oc::encrypt_to(&kp.public, b"hello e2e browser").unwrap();
            let key = oc::random_key();
            let sct = oc::encrypt_symmetric(&key, b"symmetric secret value");
            println!("{}", serde_json::json!({"priv": kp.secret_b64(), "pub": kp.public, "asym_ct": ct, "sym_key": oc::b64(&key), "sym_ct": sct}));
        }
        Some("verify-asym") => {
            let kp = oc::Keypair::from_secret_b64(&args[2]).unwrap();
            let pt = kp.decrypt(&args[3]).unwrap();
            assert_eq!(pt, args[4].as_bytes()); println!("rust-decrypt-ok: {}", String::from_utf8_lossy(&pt));
        }
        Some("verify-sym") => {
            let kb = oc::unb64(&args[2]).unwrap(); let key: [u8;32] = kb.try_into().unwrap();
            let pt = oc::decrypt_symmetric(&key, &args[3]).unwrap();
            assert_eq!(pt, args[4].as_bytes()); println!("rust-sym-ok: {}", String::from_utf8_lossy(&pt));
        }
        _ => { eprintln!("usage: gen | verify-asym <priv> <ct> <expected> | verify-sym <key> <ct> <expected>"); std::process::exit(2); }
    }
}
