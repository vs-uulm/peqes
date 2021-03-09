#[macro_use] extern crate serde_json;

use std::env;
use std::path::Path;
use std::convert::TryInto;

use sgx_crypto::key_exchange::OneWayAuthenticatedDHKE;
use sgx_crypto::random::RandomState;
use sgx_crypto::signature::SigningKey;
use sgx_crypto::certificate::X509Cert;
use sgx_crypto::digest::{sha256, Sha256Digest};

use serde::Deserialize;
use serde_json::Value;

use regex::Regex;
use hyper::header::{HeaderMap, HeaderValue};
use byteorder::{ReadBytesExt, LittleEndian};

use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{Aead, NewAead, generic_array::GenericArray};

use ring::signature::KeyPair;

#[derive(Deserialize, Debug, Clone)]
pub struct SpConfig {
    pub linkable: bool,
    pub random_nonce: bool,
    pub use_platform_service: bool,
    pub spid: String,
    pub primary_subscription_key: String,
    pub secondary_subscription_key: String,
    pub quote_trust_options: Vec<String>, 
    pub pse_trust_options: Option<Vec<String>>,
    pub sp_private_key_pem_path: String,
    pub ias_root_cert_pem_path: String,
    pub sigstruct_path: String,
}

#[derive(Deserialize, Debug)]
pub struct AttestationResponse {
    // header
    pub advisory_url: Option<String>, 
    pub advisory_ids: Option<String>, 
    pub request_id: String,

    // body
    pub id: String,
    pub timestamp: String,
    pub version: u16,
    pub isv_enclave_quote_status: String, 
    pub isv_enclave_quote_body: String,
    pub revocation_reason: Option<String>,
    pub pse_manifest_status: Option<String>,
    pub pse_manifest_hash: Option<String>,
    pub platform_info_blob: Option<String>,
    pub nonce: Option<String>,
    pub epid_pseudonym: Option<String>,
}

impl AttestationResponse {
    pub fn from_response(root_ca_cert: &X509Cert,
                         headers: &HeaderMap, 
                         body: String) -> Result<Self, AttestationError> {
        Self::verify_response(root_ca_cert, &headers, body.as_bytes())?;

        let body: Value = serde_json::from_str(&body).unwrap();

        let h = |x: &HeaderValue| x.to_str().unwrap().to_owned();
        let b = |x: &str| x.to_owned();
        Ok(
            Self {
                // header
                advisory_ids: headers.get("advisory-ids").map(h),
                advisory_url: headers.get("advisory-url").map(h),
                request_id: headers.get("request-id").map(h).unwrap(),
                // body
                id: body["id"].as_str().unwrap().to_owned(),
                timestamp: body["timestamp"].as_str().unwrap().to_owned(),
                version: body["version"].as_u64().unwrap() as u16,
                isv_enclave_quote_status: body["isvEnclaveQuoteStatus"].as_str().unwrap()
                    .to_owned(),
                    isv_enclave_quote_body: body["isvEnclaveQuoteBody"].as_str().unwrap()
                        .to_owned(),
                        revocation_reason: body["revocationReason"].as_str().map(b),
                        pse_manifest_status: body["pseManifestStatus"].as_str().map(b),
                        pse_manifest_hash: body["pseManifestHash"].as_str().map(b),
                        platform_info_blob: body["platformInfoBlob"].as_str().map(b),
                        nonce: body["nonce"].as_str().map(b),
                        epid_pseudonym: body["epidPseudonym"].as_str().map(b),
            })
    }

    fn verify_response(root_ca_cert: &X509Cert, headers: &HeaderMap, 
                       body: &[u8]) -> Result<(), AttestationError> {
        // Split certificates
        let re = Regex::new("(-----BEGIN .*-----\\n)\
                            ((([A-Za-z0-9+/]{4})*\
                              ([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)*\\n)+)\
                            (-----END .*-----)").unwrap();
        let (certificate, ca_certificate) =  {
            let c = headers.get("x-iasreport-signing-certificate")
                .unwrap().to_str().unwrap();
            let c = percent_encoding::percent_decode_str(c).decode_utf8().unwrap();
            let c = re.find_iter(&c)
                .map(|m| m.as_str().to_owned())
                .collect::<Vec<String>>();
            let mut c_iter = c.into_iter();
            let certificate = c_iter.next().unwrap();
            let certificate = X509Cert::new_from_pem(&certificate).unwrap();
            let ca_certificate = c_iter.next().unwrap();
            let ca_certificate = X509Cert::new_from_pem(&ca_certificate).unwrap();
            (certificate, ca_certificate)
        };

        // Check if the root certificate is the same as the SP-provided certificate 
        if root_ca_cert != &ca_certificate {
            return Err(AttestationError::MismatchedIASRootCertificate);
        }

        // Check if the certificate is signed by root CA
        certificate.verify_cert(&ca_certificate)
            .map_err(|_| AttestationError::InvalidIASCertificate)?;

        // Check if the signature is correct
        let verification_key = certificate.get_verification_key();
        let signature = base64::decode(
            headers.get("x-iasreport-signature").unwrap().to_str().unwrap()).unwrap();
        verification_key.verify(body, &signature[..])
            .map_err(|_| AttestationError::BadSignature)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum AttestationError {
    IO(std::io::Error),
    Reqwest(reqwest::Error),
    JSON(serde_json::Error),
    Base64(base64::DecodeError),
    String(std::string::FromUtf8Error),
    KeError(sgx_crypto::key_exchange::KeError),
    HexError(hex::FromHexError),
    SigError(sgx_crypto::signature::SigError),
    CertError(sgx_crypto::certificate::CertError),
    IASConnection(http::StatusCode),
    AESError(aes_gcm::aead::Error),
    RingError(ring::error::Unspecified),
    KeyRejected(ring::error::KeyRejected),
    Unit(()),
    IntegrityError,
    SigstructMismatched,
    EnclaveInDebugMode,
    EnclaveNotTrusted,
    PseNotTrusted,
    MismatchedIASRootCertificate,
    InvalidIASCertificate,
    BadSignature,
}

impl std::convert::From<std::io::Error> for AttestationError {
    fn from(e: std::io::Error) -> Self { Self::IO(e) }
}

impl std::convert::From<reqwest::Error> for AttestationError {
    fn from(e: reqwest::Error) -> Self { Self::Reqwest(e) }
}

impl std::convert::From<serde_json::Error> for AttestationError {
    fn from(e: serde_json::Error) -> Self { Self::JSON(e) }
}

impl std::convert::From<base64::DecodeError> for AttestationError {
    fn from(e: base64::DecodeError) -> Self { Self::Base64(e) }
}

impl std::convert::From<std::string::FromUtf8Error> for AttestationError {
    fn from(e: std::string::FromUtf8Error) -> Self { Self::String(e) }
}

impl std::convert::From<sgx_crypto::key_exchange::KeError> for AttestationError {
    fn from(e: sgx_crypto::key_exchange::KeError) -> Self { Self::KeError(e) }
}

impl std::convert::From<hex::FromHexError> for AttestationError {
    fn from(e: hex::FromHexError) -> Self { Self::HexError(e) }
}

impl std::convert::From<sgx_crypto::signature::SigError> for AttestationError {
    fn from(e: sgx_crypto::signature::SigError) -> Self { Self::SigError(e) }
}

impl std::convert::From<sgx_crypto::certificate::CertError> for AttestationError {
    fn from(e: sgx_crypto::certificate::CertError) -> Self { Self::CertError(e) }
}

impl std::convert::From<aes_gcm::aead::Error> for AttestationError {
    fn from(e: aes_gcm::aead::Error) -> Self { Self::AESError(e) }
}

impl std::convert::From<ring::error::Unspecified> for AttestationError {
    fn from(e: ring::error::Unspecified) -> Self { Self::RingError(e) }
}

impl std::convert::From<ring::error::KeyRejected> for AttestationError {
    fn from(e: ring::error::KeyRejected) -> Self { Self::KeyRejected(e) }
}

impl std::convert::From<()> for AttestationError {
    fn from(e: ()) -> Self { Self::Unit(e) }
}

fn parse_config_file(path: &str) -> SpConfig {
    serde_json::from_reader(std::fs::File::open(path).unwrap()).unwrap()
}


// todo: this thing requires heavy clean up
#[tokio::main]
async fn main() -> Result<(), AttestationError> {
    let mut args: Vec<String> = env::args().collect();

    let mut skip = false;
    if args.len() == 4 && args[3] == "--skip-attestation" {
        skip = true;
        args.pop();
    }

    if args.len() != 3 || !args[2].starts_with("--hash=") {
        eprintln!("Usage: {} STUDY_URL --hash=STUDY_HASH [--skip-attestation]", args[0]);
        std::process::exit(-1);
    }

    let study_url = args[1].to_string();
    let study_hash = hex::decode(args[2][7..].to_string())?;

    let client = reqwest::Client::new();

    let study_json = client.get(&study_url).send().await?.text().await?;

    let hash = ring::digest::digest(&ring::digest::SHA256, &study_json.as_bytes());
    if hash.as_ref() != &study_hash[..] {
        return Err(AttestationError::IntegrityError);
    }

    if !skip {
        let config = parse_config_file("data/settings.json");
        println!("config: {:?}", config);
        let sp_private_key = SigningKey::new_from_pem_file(Path::new(&config.sp_private_key_pem_path))?;
        let cert = X509Cert::new_from_pem_file(Path::new(&config.ias_root_cert_pem_path))?;

        let study: serde_json::Value = serde_json::from_str(&study_json)?;
        let public_key = base64::decode(study.get("public_key").ok_or(())?.as_str().ok_or(())?)?;

        let msg01 = client.get(&format!("{}/approve", study_url))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let id = msg01.get("id").ok_or(())?.as_str().ok_or(())?;
        let ga = base64::decode(msg01.get("Ga").ok_or(())?.as_str().ok_or(())?)?;
        let gid = base64::decode(msg01.get("GID").ok_or(())?.as_str().ok_or(())?)?;

        // retrieve sigrl
        let url = format!("https://api.trustedservices.intel.com/sgx/dev/attestation/v3/sigrl/{:02x}{:02x}{:02x}{:02x}", gid[0], gid[1], gid[2], gid[3]);
        let sigrl = client.get(&url)
            .header("Ocp-Apim-Subscription-Key", &config.primary_subscription_key)
            .send()
            .await?
            .text()
            .await?;

        let rng = RandomState::new();
        let key_exchange = OneWayAuthenticatedDHKE::generate_keypair(&rng)?;
        let g_b = key_exchange.get_public_key().to_owned();
        let spid = hex::decode(&config.spid)?;
        let quote_type = config.linkable as u16;

        let mut aad = Vec::new();
        aad.extend_from_slice(&spid[..]);
        aad.extend_from_slice(&quote_type.to_le_bytes()[..]);

        let mut g_a = [0 as u8; 65];
        g_a.copy_from_slice(&ga);

        let (kdk, signature) = key_exchange.sign_and_derive(&g_a, &sp_private_key, Some(&aad[..]), &rng)?;
        // todo hmac??

        let msg2 = json!({
            "Gb": base64::encode(&g_b[..]),
            "SPID": base64::encode(&spid),
            "TYPE": quote_type,
            "SigSP": base64::encode(&signature),
            "SigRL": sigrl
        });

        let msg3 = client.put(&format!("{}/approve/{}", study_url, id))
            .json(&msg2)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let _ga = base64::decode(msg3.get("Ga").ok_or(())?.as_str().ok_or(())?)?;
        let quote = base64::decode(msg3.get("QUOTE").ok_or(())?.as_str().ok_or(())?)?;
        let ps_sec_prop = base64::decode(msg3.get("PS_SEC_PROP").ok_or(())?.as_str().ok_or(())?)?;

        // integrity check
        let quote_digest: Sha256Digest = (&quote[368..400]).try_into().unwrap();

        let mut ga_gb = Vec::new();
        ga_gb.extend_from_slice(&g_a);
        ga_gb.extend_from_slice(&g_b);
        ga_gb.extend_from_slice(&ps_sec_prop);

        let verification_digest = sha256(&ga_gb);
        if verification_digest != quote_digest {
            return Err(AttestationError::IntegrityError);
        }

        // Verify attestation evidence
        let resp = client.post("https://api.trustedservices.intel.com/sgx/dev/attestation/v3/report")
            .header("Ocp-Apim-Subscription-Key", &config.primary_subscription_key)
            .json(&json!({ "isvEnclaveQuote": msg3.get("QUOTE") }))
            .send()
            .await?;

        if resp.status() != 200 {
            return Err(AttestationError::IASConnection(resp.status()));
        }

        let headers = resp.headers().clone();
        let body = resp.text().await?;

        let attestation_result = AttestationResponse::from_response(&cert, &headers, body)?;

        eprintln!("==============Attestation Result==============");
        eprintln!("{:#?}", attestation_result);
        eprintln!("==============================================");

        // verify enclave identity
        let mrenclave = &quote[112..144];
        let mrsigner = &quote[176..208];
        let isvprodid = (&quote[304..306]).read_u16::<LittleEndian>().unwrap();
        let isvsvn = (&quote[306..308]).read_u16::<LittleEndian>().unwrap();

        println!("mrenclave: {:x?}", mrenclave);
        println!("mrsigner: {:x?}", mrsigner);
        println!("isvprodid: {:x?}", isvprodid);
        println!("isvsvn: {:x?}", isvsvn);
        eprintln!("==============================================");

        // decide whether to trust enclave
        let quote_status = attestation_result.isv_enclave_quote_status.clone();
        let pse_manifest_status = attestation_result.pse_manifest_status.clone();
        let is_enclave_trusted = (quote_status == "OK") || config.quote_trust_options.iter().any(|e| e == &quote_status);
        let is_pse_manifest_trusted = pse_manifest_status.map(|status| (status == "OK") || config.pse_trust_options.as_ref().unwrap().iter().any(|e| e == &status));

        println!("is_enclave_trusted: {:?}", is_enclave_trusted);
        println!("is_pse_manifest_trusted: {:?}", is_pse_manifest_trusted);
        println!("platform_info_blob: {:?}", attestation_result.platform_info_blob);
        println!("epid_pseudonym: {:?}", attestation_result.epid_pseudonym);

        eprintln!("==============================================");

        if !is_enclave_trusted {
            return Err(AttestationError::EnclaveNotTrusted);
        }
        if let Some(trusted) = is_pse_manifest_trusted {
            if !trusted {
                return Err(AttestationError::PseNotTrusted);
            }
        }

        // sigma protocol to prove that enclave owns private key
        let challenge: [u8; 32] = rand::random();
        let nonce: [u8; 12] = rand::random();

        let aead = Aes128Gcm::new(GenericArray::clone_from_slice(&kdk));
        let nonce = GenericArray::from_slice(&nonce);
        let ciphertext = aead.encrypt(nonce, &challenge[..])?;

        let msg4 = json!({
            "nonce": base64::encode(&nonce),
            "challenge": base64::encode(&ciphertext)
        });

        let res = client.post(&format!("{}/approve/{}", study_url, id))
            .json(&msg4)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let response = base64::decode(res.get("response").ok_or(())?.as_str().ok_or(())?)?;
        let auth = base64::decode(res.get("auth").ok_or(())?.as_str().ok_or(())?)?;

        // verifiy knowledge of kdk
        let key = ring::hmac::VerificationKey::new(&ring::digest::SHA512, &kdk);
        ring::hmac::verify(&key, &response, &auth)?;

        // verify response
        let peer_public_key = untrusted::Input::from(&public_key);
        let msg = untrusted::Input::from(&challenge);
        let sig = untrusted::Input::from(&response);
        ring::signature::verify(&ring::signature::ECDSA_P256_SHA256_ASN1, peer_public_key, msg, sig)?;
    }

    // sigma proof successful, create study certificate
    let rng = ring::rand::SystemRandom::new();
    let sk = std::fs::read_to_string("data/secret-key.pem")?;
    let keypair = base64::decode(&sk)?;
    let keypair = untrusted::Input::from(&keypair);
    let keypair = ring::signature::EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, keypair)?;
    let csr = untrusted::Input::from(&study_json.as_bytes());
    let signature = keypair.sign(&rng, csr)?;

    let approval = json!({
        "pk": base64::encode(keypair.public_key().as_ref()),
        "cert": base64::encode(signature.as_ref())
    });

    let resp = client.put(&study_url)
        .json(&approval)
        .send()
        .await?;

    if resp.status() != 200 {
        return Err(AttestationError::IASConnection(resp.status()));
    }

    let resp = resp.text().await?;
    println!("response: {}", resp);

    println!("Study successfully approved!");
    Ok(())
}
