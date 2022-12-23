use hex_literal::hex;
use k256::schnorr::signature::Signature;
use k256::schnorr::{signature::Verifier, SigningKey, VerifyingKey};

const KEY: [u8; 32] = hex!("0000000000000000000000000000000000000000000000000000000000000003");
const PUBLIC_KEY: [u8; 32] =
    hex!("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
const CONTENTS: [u8; 32] = hex!("0000000000000000000000000000000000000000000000000000000000000000");
const AUX_RAND: [u8; 32] = hex!("0000000000000000000000000000000000000000000000000000000000000000");
const SIGNATURE: [u8; 64] = hex!("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0");

fn sign() {
    println!("key: {:?}", KEY);
    println!("contents: {:?}", CONTENTS);
    println!("aux_rand: {:?}", AUX_RAND);
    println!("expected_signature: {:?}", SIGNATURE);

    // from https://docs.rs/k256/latest/src/k256/schnorr.rs.html#268
    let sk = SigningKey::from_bytes(&KEY).unwrap();

    let sig = sk
        .try_sign_prehashed(&CONTENTS, &AUX_RAND)
        .unwrap_or_else(|_| panic!("low-level Schnorr signing failure for index"));

    println!("sig: {:?}", sig);

    if sig.as_ref() == SIGNATURE {
        println!("SUCCESS")
    } else {
        println!("BOOO")
    }
}

fn verify() -> Result<(), k256::ecdsa::Error> {
    let signature = Signature::from_bytes(&SIGNATURE).unwrap();
    let verifying_key = VerifyingKey::from_bytes(&PUBLIC_KEY).unwrap();

    println!("signature {:?}", signature);
    println!("verifying_key {:?}", verifying_key);

    let results = verifying_key.verify(&CONTENTS, &signature);

    results
}

fn main() {
    sign();

    let verify_results = verify();

    println!("{:?}", verify_results);
}
