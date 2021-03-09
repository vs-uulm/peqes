use serde::{Deserialize, Serialize};
use serde_json::Value;

use std::collections::HashMap;
use super::crypto;

#[derive(Serialize, Deserialize)]
pub enum StudyStatus {
    New,
    Approved,
    Completed
}

#[derive(Serialize, Deserialize)]
pub struct Study {
    pub name: String,
    pub description: String,
    pub questionnaire: serde_json::Value,
    pub analysis: String,

    researcher_identity: String,
    researcher_signature: String,

    pub keypair: Vec<u8>,
    pub certificate: Option<Vec<u8>>,
    pub result: Option<String>,
    pub status: StudyStatus,
    pub response_count: u32,

    pub hash: Vec<u8>,
    sealing_key: [u8; 16],

    #[serde(skip_serializing, skip_deserializing)]
    pending_responses: HashMap<String, crypto::KeyExchange>,

    #[serde(skip_serializing, skip_deserializing)]
    pub responses: Vec<Vec<u8>>,

    #[serde(skip_serializing, skip_deserializing)]
    pub dirty: bool
}

impl Study {
    pub fn new(name: String, description: String, questionnaire: serde_json::Value, analysis: String, researcher_identity: String, researcher_signature: String) -> Result<Study, crypto::CryptoError> {
        let data = json!({
            "name": name,
            "description": description,
            "questionnaire": questionnaire,
            "analysis": analysis,
        }).to_string();

        // verify that researcher signature matches identity
        let pk = base64::decode(&researcher_identity).map_err(|_| crypto::CryptoError {})?;
        let sig = base64::decode(&researcher_signature).map_err(|_| crypto::CryptoError {})?;
        crypto::verify_certificate(&pk, data.as_bytes(), &sig)?;

        Ok(Study {
            name: name,
            description: description,
            questionnaire: questionnaire,
            analysis: analysis,
            researcher_identity: researcher_identity,
            researcher_signature: researcher_signature,
            keypair: crypto::gen_keypair()?,
            certificate: None,
            responses: vec![],
            response_count: 0,
            status: StudyStatus::New,
            result: None,
            hash: vec![0; ring::digest::SHA512_OUTPUT_LEN],
            sealing_key: crypto::random_key(),
            pending_responses: HashMap::new(),
            dirty: true
        })
    }

    pub fn from_json(json: &serde_json::Value) -> Result<Study, crypto::CryptoError> {
        match (json.get("name"), json.get("description"), json.get("questionnaire"), json.get("analysis"), json.get("researcher_identity"), json.get("researcher_signature")) {
            (
                Some(serde_json::Value::String(name)),
                Some(serde_json::Value::String(description)),
                Some(serde_json::Value::Object(questionnaire)),
                Some(serde_json::Value::String(analysis)),
                Some(serde_json::Value::String(researcher_identity)),
                Some(serde_json::Value::String(researcher_signature)),
            ) => Study::new(
                    name.to_string(),
                    description.to_string(),
                    json!(questionnaire),
                    analysis.to_string(),
                    researcher_identity.to_string(),
                    researcher_signature.to_string()
            ),

            _ => Err(crypto::CryptoError {})
        }
    }

    pub fn add_certificate(&mut self, pk: &[u8], cert: Vec<u8>) -> Result<(), ()> {
        // todo verify pk?
        let csr = self.to_signing_request();

        match self.status {
            StudyStatus::New => {
                match crypto::verify_certificate(&pk, csr.as_bytes(), &cert) {
                    Err(_) => Err(()),

                    Ok(_) => {
                        self.status = StudyStatus::Approved;
                        self.certificate = Some(cert);
                        self.dirty = true;

                        Ok(())
                    }
                }
            },

            _ => Err(())
        }
    }

    pub fn to_signing_request(&self) -> String {
        let mut signing_request = self.to_json();
        signing_request.as_object_mut().unwrap().remove("status");
        signing_request.as_object_mut().unwrap().remove("result");
        signing_request.as_object_mut().unwrap().remove("certificate");
        signing_request.as_object_mut().unwrap().remove("response_count");
        signing_request.to_string()
    }

    pub fn to_json(&self) -> Value {
        let pk = crypto::get_base64_public_key(&self.keypair);

        let cert = match &self.certificate {
            Some(cert) => json!(base64::encode(&cert)),
            None => json!(null)
        };

        json!({
            "name": self.name,
            "status": self.status,
            "result": self.result,
            "description": self.description,
            "questionnaire": self.questionnaire,
            "analysis": self.analysis,
            "researcher_identity": self.researcher_identity,
            "researcher_signature": self.researcher_signature,
            "public_key": pk,
            "certificate": cert,
            "response_count": self.response_count
        })
    }

    pub fn sign_response(&self, data: &[u8]) -> Result<Vec<u8>, crypto::CryptoError> {
        crypto::sign(&self.keypair, data)
    }

    pub fn initiate_response(&mut self) -> Result<(String, String, String), crypto::CryptoError> {
        let (my_private_key, my_public_key, signature) = crypto::start_signed_key_exchange(&self.keypair)?;
        let id = uuid::Uuid::new_v4().to_hyphenated().to_string();

        // todo garbage collection for unused pending keys
        self.pending_responses.insert(id.to_string(), my_private_key);
        Ok((id, my_public_key, signature))
    }

    pub fn submit_response(&mut self, response: &str, peer_pk: &[u8], data: &[u8], nonce: &[u8]) -> Result<(), crypto::CryptoError> {
        match self.pending_responses.remove(response) {
            None => Err(crypto::CryptoError {}),
            Some(my_private_key) => {
                // decrypt response
                let shared_secret = crypto::complete_key_exchange(my_private_key, peer_pk)?;
                let response = crypto::decrypt_to_string(&shared_secret, data, nonce)?;

                // seal response
                let nonce = crypto::nonce();
                let sealed = crypto::encrypt(&self.sealing_key, response.as_bytes(), &nonce)?;

                // store sealed response
                let mut tmp: Vec<u8> = Vec::with_capacity(self.hash.len() + nonce.len() + 8 + sealed.len());
                tmp.extend_from_slice(&self.hash);
                tmp.extend_from_slice(&nonce);
                tmp.extend_from_slice(&usize::to_be_bytes(sealed.len()));
                tmp.extend_from_slice(&sealed);
                self.responses.push(tmp);
                self.response_count += 1;

                // update hash
                let mut data = Vec::with_capacity(self.hash.len() + response.as_bytes().len());
                data.extend_from_slice(&self.hash);
                data.extend_from_slice(response.as_bytes());
                self.hash = ring::digest::digest(&ring::digest::SHA512, &data).as_ref().to_vec();
                self.dirty = true;

                Ok(())
            }
        }
    }

    pub fn auth_researcher(&self, auth: &str) -> Result<(), crypto::CryptoError> {
        let sig = base64::decode(&auth).map_err(|_| crypto::CryptoError {})?;
        let pk = base64::decode(&self.researcher_identity).map_err(|_| crypto::CryptoError {})?;
        let data = crypto::get_base64_public_key(&self.keypair);
        let data = base64::decode(&data).map_err(|_| crypto::CryptoError {})?;

        crypto::verify_certificate(&pk, &data, &sig)?;
        Ok(())
    }

    pub fn complete_study(&mut self, mut responses: Vec<u8>) -> Result<String, crypto::CryptoError> {
        use std::convert::TryInto;
        let jstat = include_str!("jstat.js");

        match self.status {
            StudyStatus::New => Err(crypto::CryptoError {}),
            StudyStatus::Completed => Err(crypto::CryptoError {}),
            StudyStatus::Approved => {
                let mut compare_hash = [0u8; ring::digest::SHA512_OUTPUT_LEN];
                let mut data = String::from("const results = []; const pushResult = r => results.push(r); const data = [\n");

                while !responses.is_empty() {
                    let mut hash = responses;
                    let mut nonce = hash.split_off(ring::digest::SHA512_OUTPUT_LEN);
                    let mut size = nonce.split_off(12);
                    let mut sealed = size.split_off(8);

                    let size = usize::from_be_bytes(size[..].try_into().unwrap());
                    responses = sealed.split_off(size);

                    // validate merkle tree
                    if hash.as_slice() != &compare_hash[..] {
                        return Err(crypto::CryptoError {});
                    }

                    // update compare hash
                    let unsealed = crypto::decrypt(&self.sealing_key, &sealed, &nonce)?;
                    let mut info = Vec::with_capacity(compare_hash.len() + unsealed.len());
                    info.extend_from_slice(&compare_hash);
                    info.extend_from_slice(&unsealed);
                    compare_hash.copy_from_slice(ring::digest::digest(&ring::digest::SHA512, &info).as_ref());

                    // append to data array
                    let response = String::from_utf8(unsealed).map_err(|_| crypto::CryptoError {})?;
                    data.push_str(&response);
                    data.push_str(",\n");
                }

                // final merkle tree validation
                if self.hash.as_slice() != &compare_hash[..] {
                    return Err(crypto::CryptoError {});
                }

                data.push_str("];");

                // append analysis script
                data.push_str("try {");
                data.push_str(&self.analysis);
                data.push_str("} catch(e) {");
                data.push_str("pushResult('error' + e.toString());"); // todo only for debugging
                data.push_str("};");

                // return results in the end
                data.push_str("JSON.stringify(results)");

                let ctx = quickjs_rs::Context::new();

                // preload jstat library
                let _ = ctx.eval(&jstat);

                // load responses and execute analysis script
                let res = ctx.eval(&data).unwrap();

                self.result = Some(res.to_string());
                self.status = StudyStatus::Completed;
                self.dirty = true;

                Ok(res)
            }
        }
    }
}
