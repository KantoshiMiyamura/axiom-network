// Test-only helper. Two modes:
//   gen-addr                            -> generate fresh keypair, print address only
//   gen-addr --create <path> <password> -> create encrypted wallet at <path>, print address
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 4 && args[1] == "--create" {
        let path = &args[2];
        let password = &args[3];
        let kp = axiom_wallet::KeyPair::generate().expect("keygen");
        let priv_bytes = kp.export_private_key().to_vec();
        let ks = axiom_wallet::create_keystore(&priv_bytes, password).expect("encrypt");
        let json = serde_json::to_string_pretty(&ks).expect("json");
        std::fs::write(path, json).expect("write wallet");
        let addr = axiom_wallet::Address::from_pubkey_hash(kp.public_key_hash());
        println!("{}", addr);
    } else {
        let kp = axiom_wallet::KeyPair::generate().expect("keygen");
        let addr = axiom_wallet::Address::from_pubkey_hash(kp.public_key_hash());
        println!("{}", addr);
    }
}
