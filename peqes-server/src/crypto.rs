pub type CryptoError = ring::error::Unspecified;
pub type KeyExchange = ring::agreement::EphemeralPrivateKey;

use aes_gcm::{Aes128Gcm, Aes256Gcm};
use aes_gcm::aead::{Aead, NewAead, generic_array::GenericArray};
use serde::{Deserialize, Serialize};
use untrusted;

#[cfg(target_env = "sgx")]
use sgx_isa::ErrorCode;

#[derive(Debug, PartialEq)]
struct DerivedKey<T: core::fmt::Debug + PartialEq>(T);

pub fn gen_keypair() -> Result<Vec<u8>, ring::error::Unspecified> {
    let rng = ring::rand::SystemRandom::new();
    let keypair = ring::signature::EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng)?;

    Ok(Vec::from(keypair.as_ref()))
}

pub fn verify_certificate(pk: &[u8], data: &[u8], cert: &[u8]) -> Result<(), ring::error::Unspecified> {
    let pk = untrusted::Input::from(pk.as_ref());
    let data = untrusted::Input::from(data.as_ref());
    let cert = untrusted::Input::from(cert.as_ref());
    ring::signature::verify(&ring::signature::ECDSA_P256_SHA256_ASN1, pk, data, cert)
}

pub fn get_base64_public_key(keypair: &[u8]) -> String {
    let keypair = untrusted::Input::from(keypair.as_ref());
    match ring::signature::EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, keypair) {
        Ok(keypair) => base64::encode(ring::signature::KeyPair::public_key(&keypair)),
        _ => "".to_string()
    }
}

pub fn sign(signing_keypair: &[u8], data: &[u8]) -> Result<Vec<u8>, ring::error::Unspecified> {
    let rng = ring::rand::SystemRandom::new();
    let signing_keypair = untrusted::Input::from(signing_keypair.as_ref());
    let keypair = ring::signature::EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, signing_keypair)?;
    let signature = keypair.sign(&rng, untrusted::Input::from(&data))?;

    Ok(signature.as_ref().to_vec())
}

pub fn start_signed_key_exchange(signing_keypair: &[u8]) -> Result<(KeyExchange, String, String), ring::error::Unspecified> {
    let signing_keypair = untrusted::Input::from(signing_keypair.as_ref());

    let rng = ring::rand::SystemRandom::new();
    let my_private_key = ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::ECDH_P256, &rng)?;
    let my_public_key = my_private_key.compute_public_key()?;

    let keypair = ring::signature::EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, signing_keypair)?;
    let signature = keypair.sign(&rng, untrusted::Input::from(my_public_key.as_ref()))?;

    Ok((my_private_key, base64::encode(&my_public_key), base64::encode(&signature)))
}

pub fn complete_key_exchange(my_private_key: ring::agreement::EphemeralPrivateKey, peqes_pk: &[u8]) -> Result<Vec<u8>, ring::error::Unspecified> {
    let my_public_key = my_private_key.compute_public_key()?;
    let peqes_public_key = untrusted::Input::from(peqes_pk.as_ref());

    ring::agreement::agree_ephemeral(
        my_private_key,
        &ring::agreement::ECDH_P256,
        peqes_public_key,
        ring::error::Unspecified,
        |key_material| {
            let info = [my_public_key.as_ref(), peqes_pk].concat();

            let mut shared_key = [0; 32];
            let salt = ring::hmac::SigningKey::new(&ring::digest::SHA512, &[]);
            ring::hkdf::extract_and_expand(&salt, key_material, &info, &mut shared_key);

            Ok(shared_key.to_vec())
        }
    )
}

pub fn decrypt_to_string(shared_secret: &[u8], data: &[u8], nonce: &[u8]) -> Result<String, ring::error::Unspecified> {
    let key = GenericArray::clone_from_slice(&shared_secret);
    let nonce = GenericArray::from_slice(&nonce);
    let decrypted = match Aes256Gcm::new(key).decrypt(nonce, data) {
        Err(_) => return Err(ring::error::Unspecified {}),
        Ok(decrypted) => decrypted
    };

    match std::str::from_utf8(&decrypted) {
        Err(_) => Err(ring::error::Unspecified {}),
        Ok(response) => Ok(response.to_string())
    }
}

pub fn encrypt(key: &[u8], plaintext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, ring::error::Unspecified> {
    let key = GenericArray::clone_from_slice(key);
    let aead = Aes128Gcm::new(key);
    let nonce = GenericArray::from_slice(&nonce);
    match aead.encrypt(nonce, plaintext) {
        Err(_) => Err(ring::error::Unspecified {}),
        Ok(ciphertext) => Ok(ciphertext.to_vec())
    }
}

pub fn decrypt(key: &[u8], ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, ring::error::Unspecified> {
    let key = GenericArray::clone_from_slice(key);
    let aead = Aes128Gcm::new(key);
    let nonce = GenericArray::from_slice(&nonce);
    match aead.decrypt(nonce, ciphertext) {
        Err(_) => Err(ring::error::Unspecified {}),
        Ok(plaintext) => Ok(plaintext.to_vec())
    }
}

pub fn hmac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, ring::error::Unspecified> {
    let key = ring::hmac::SigningKey::new(&ring::digest::SHA512, &key);
    let signature = ring::hmac::sign(&key, &data);

    Ok(signature.as_ref().to_vec())
}

pub fn nonce() -> [u8; 12] {
    rand::random()
}

pub fn random_key() -> [u8; 16] {
    rand::random()
}

#[derive(Debug)]
pub struct SealData {
    rand: [u8; 16],
    pub nonce: [u8; 12],
    isvsvn: u16,
    cpusvn: [u8; 16],
    attributes: [u8; 16],
    miscselect: u32
}

impl Serialize for SealData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
        let mut vec: Vec<u8> = Vec::with_capacity(66);
        vec.extend_from_slice(&self.rand);
        vec.extend_from_slice(&self.nonce);
        vec.extend_from_slice(&self.isvsvn.to_be_bytes());
        vec.extend_from_slice(&self.cpusvn);
        vec.extend_from_slice(self.attributes.as_ref());
        //vec.extend_from_slice(&self.miscselect.bits().to_be_bytes());
        vec.extend_from_slice(&self.miscselect.to_be_bytes());
        let s = base64::encode(&vec);
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for SealData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: serde::Deserializer<'de> {
        use serde::de::Error;
        use std::convert::TryInto;

        let s = String::deserialize(deserializer)?;
        let vec = base64::decode(&s).map_err(D::Error::custom)?;

        let rand: [u8; 16] = vec[0..16].try_into().map_err(D::Error::custom)?;
        let nonce: [u8; 12] = vec[16..28].try_into().map_err(D::Error::custom)?;
        let isvsvn: [u8; 2] = vec[28..30].try_into().map_err(D::Error::custom)?;
        let isvsvn = u16::from_be_bytes(isvsvn);
        let cpusvn: [u8; 16] = vec[30..46].try_into().map_err(D::Error::custom)?;
        let attributes: [u8; 16] = vec[46..62].try_into().map_err(D::Error::custom)?;
        let miscselect: [u8; 4] = vec[62..66].try_into().map_err(D::Error::custom)?;
        let miscselect = u32::from_be_bytes(miscselect);

        Ok(SealData {
            rand: rand,
            nonce: nonce,
            isvsvn: isvsvn,
            cpusvn: cpusvn,
            attributes: attributes,
            miscselect: miscselect
        })
    }
}

#[cfg(target_env = "sgx")]
fn egetkey(label: [u8; 16], seal_data: &SealData) -> Result<[u8; 16], ErrorCode> {
    use sgx_isa::{Keyname, Keypolicy, Keyrequest};

    let mut keyid = [0; 32];
    {
        let (label_dst, rand_dst) = keyid.split_at_mut(16);
        label_dst.copy_from_slice(&label);
        rand_dst.copy_from_slice(&seal_data.rand);
    }

    Keyrequest {
        keyname: Keyname::Seal as _,
        keypolicy: Keypolicy::MRENCLAVE,
        isvsvn: seal_data.isvsvn,
        cpusvn: seal_data.cpusvn,
        attributemask: [!0; 2],
        keyid: keyid,
        miscmask: !0,
        ..Default::default()
    }.egetkey()

    // Ok([0 as u8; 16]) // todo xxx remove
}

#[cfg(target_env = "sgx")]
pub fn seal_key(label: [u8; 16]) -> ([u8; 16], SealData) {
    use std::convert::TryInto;
    use rand::random;

    let report = sgx_isa::Report::for_self();
    let seal_data = SealData {
        rand: random(),
        nonce: random(),
        isvsvn: report.isvsvn,
        cpusvn: report.cpusvn,
        attributes: report.attributes.as_ref().try_into().unwrap(),
        miscselect: report.miscselect.bits(),
    };

    (egetkey(label, &seal_data).unwrap(), seal_data)
}

#[cfg(target_env = "sgx")]
pub fn unseal_key(label: [u8; 16], seal_data: SealData) -> Result<[u8; 16], ErrorCode> {
    let attributes = sgx_isa::Attributes::try_copy_from(&seal_data.attributes)
        .ok_or(ErrorCode::InvalidAttribute)?;

    let miscselect = sgx_isa::Miscselect::from_bits(seal_data.miscselect)
        .ok_or(ErrorCode::InvalidAttribute)?;

    let report = sgx_isa::Report::for_self();

    if report.attributes != attributes || report.miscselect != miscselect {
        return Err(ErrorCode::InvalidAttribute)
    }

    egetkey(label, &seal_data)
}
