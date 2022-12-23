use hex_literal::hex;
use k256::schnorr::{
    signature::{Signer, Verifier},
    SigningKey, VerifyingKey,
};

fn main() {
    let key = hex!("0000000000000000000000000000000000000000000000000000000000000003");
    let contents = hex!("0000000000000000000000000000000000000000000000000000000000000000");
    let aux_rand = hex!("0000000000000000000000000000000000000000000000000000000000000000");
    let expected_signature = hex!("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0");

    println!("key: {:?}", key);
    println!("contents: {:?}", contents);
    println!("aux_rand: {:?}", aux_rand);
    println!("expected_signature: {:?}", expected_signature);

    // from https://docs.rs/k256/latest/src/k256/schnorr.rs.html#268
    let sk = SigningKey::from_bytes(&key).unwrap();

    let sig = sk
        .try_sign_prehashed(&contents, &aux_rand)
        .unwrap_or_else(|_| panic!("low-level Schnorr signing failure for index"));

    println!("sig: {:?}", sig);

    if sig.as_ref() == expected_signature {
        println!("SUCCESS")
    } else {
        println!("BOOO")
    }
}
