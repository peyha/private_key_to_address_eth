extern crate secp256k1;
extern crate hex;
extern crate sha3;

use secp256k1::Secp256k1;
use secp256k1::key::SecretKey;
use hex::decode;
use sha3::{Digest, Keccak256};

fn private_key_to_ethereum_address(private_key_hex: &str) -> Option<String> {
    let secp = Secp256k1::new();
    let private_key_bytes = decode(private_key_hex).ok()?;
    let secret_key = SecretKey::from_slice(&private_key_bytes).ok()?;
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

    let address_bytes = Keccak256::digest(&public_key.serialize_uncompressed()[1..]);
    let address_hex = hex::encode(&address_bytes[12..]); // Take the last 20 bytes

    Some(format!("0x{}", address_hex))
}

fn main() {
    let private_key_hex = "9c7b691152f1b1c025dbf6a24da3c8475dd83f4ff5064c3f5dff262abf2f507c"; // Replace with the private key
    if let Some(ethereum_address) = private_key_to_ethereum_address(private_key_hex) {
        println!("The Ethereum address corresponding to the private key is: {}", ethereum_address);
    } else {
        eprintln!("Invalid private key or an error occurred.");
    }
}

