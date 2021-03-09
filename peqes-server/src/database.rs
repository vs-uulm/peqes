use std::collections::HashMap;
use uuid::Uuid;
use std::io::Write;

use crate::studies::Study;

#[cfg(target_env = "sgx")]
use std::net::TcpStream;

#[cfg(target_env = "sgx")]
use std::io::Read;

#[cfg(target_env = "sgx")]
use crate::crypto;

#[derive(Debug)]
pub enum DatabaseError {
    IO(std::io::Error),
    UUID(uuid::Error),
    JSON(serde_json::Error),
    Base64(base64::DecodeError),
    String(std::string::FromUtf8Error),
    SGX(sgx_isa::ErrorCode),
    Crypto(ring::error::Unspecified)
}

impl std::convert::From<std::io::Error> for DatabaseError {
    fn from(e: std::io::Error) -> Self { Self::IO(e) }
}

impl std::convert::From<uuid::Error> for DatabaseError {
    fn from(e: uuid::Error) -> Self { Self::UUID(e) }
}

impl std::convert::From<serde_json::Error> for DatabaseError {
    fn from(e: serde_json::Error) -> Self { Self::JSON(e) }
}

impl std::convert::From<base64::DecodeError> for DatabaseError {
    fn from(e: base64::DecodeError) -> Self { Self::Base64(e) }
}

impl std::convert::From<std::string::FromUtf8Error> for DatabaseError {
    fn from(e: std::string::FromUtf8Error) -> Self { Self::String(e) }
}

impl std::convert::From<sgx_isa::ErrorCode> for DatabaseError {
    fn from(e: sgx_isa::ErrorCode) -> Self { Self::SGX(e) }
}

impl std::convert::From<ring::error::Unspecified> for DatabaseError {
    fn from(e: ring::error::Unspecified) -> Self { Self::Crypto(e) }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[cfg(target_env = "sgx")]
pub struct Database {
    info: crypto::SealData,
    data: String
}

#[cfg(target_env = "sgx")]
fn write_db(stream: Option<&mut TcpStream>, req_type: u8, uuid: &Uuid, data: &[u8]) -> Result<(), DatabaseError> {
    if let Some(stream) = stream {
        stream.write_all(&[req_type])?;
        stream.write_all(uuid.as_bytes())?;
        stream.write_all(&usize::to_be_bytes(data.len()))?;
        stream.write_all(data)?;
    }

    Ok(())
}

#[cfg(target_env = "sgx")]
impl Database {
    pub fn restore() -> Result<HashMap<String, Study>, DatabaseError> {
        let mut studies = HashMap::new();

        let mut stream = TcpStream::connect("database")?;
        stream.write_all(&[0])?;

        let mut count = [0 as u8; 8];
        stream.read_exact(&mut count)?;
        let count = usize::from_be_bytes(count);

        for _ in 0..count {
            let mut uuid = [0 as u8; 16];
            stream.read_exact(&mut uuid)?;
            let uuid = Uuid::from_slice(&uuid)?;

            let mut size = [0 as u8; 8];
            stream.read_exact(&mut size)?;
            let size = usize::from_be_bytes(size);

            if size > 0 {
                let mut data = vec![0u8; size];
                stream.read_exact(&mut data)?;
                let json = String::from_utf8(data)?;

                let database: Database = serde_json::from_str(&json)?;

                let nonce = database.info.nonce.to_vec();
                let key = crypto::unseal_key(uuid.as_bytes().clone(), database.info)?;

                let data = base64::decode(&database.data)?;
                let data = crypto::decrypt(&key, &data, &nonce)?;
                let data = String::from_utf8(data)?;

                let study: Study = serde_json::from_str(&data)?;
                studies.insert(uuid.to_hyphenated().to_string(), study);
            }
        }

        Ok(studies)
    }

    pub fn get_responses(id: &str) -> Result<Vec<u8>, DatabaseError> {
        let uuid = Uuid::parse_str(&id)?;

        let mut stream = TcpStream::connect("database")?;
        stream.write_all(&[3])?;
        stream.write_all(uuid.as_bytes())?;

        let mut size = [0 as u8; 8];
        stream.read_exact(&mut size)?;
        let size = usize::from_be_bytes(size);

        let mut data = vec![0u8; size];
        stream.read_exact(&mut data)?;

        Ok(data)
    }

    pub fn persist(studies: &mut HashMap<String, Study>) {
        let mut stream = None;

        for (id, study) in studies.iter_mut() {
            if study.dirty {
                study.dirty = false;
                if stream.is_none() {
                    stream = match TcpStream::connect("database") {
                        Ok(s) => Some(s),
                        _ => return
                    };
                }

                if let Ok(uuid) = Uuid::parse_str(&id) {
                    while !study.responses.is_empty() {
                        let data = study.responses.remove(0);
                        let _ = write_db(stream.as_mut(), 2, &uuid, &data);
                    }

                    if let Ok(json) = serde_json::to_string(study) {
                        let (key, seal_data) = crypto::seal_key(uuid.as_bytes().clone());
                        if let Ok(data) = crypto::encrypt(&key, json.as_bytes(), &seal_data.nonce) {
                            let sealed = Database {
                                info: seal_data,
                                data : base64::encode(&data)
                            };

                            if let Ok(json) = serde_json::to_string(&sealed) {
                                let _ = write_db(stream.as_mut(), 1, &uuid, json.as_bytes());
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(not(target_env = "sgx"))]
pub struct Database { }

#[cfg(not(target_env = "sgx"))]
impl Database {
    pub fn restore() -> Result<HashMap<String, Study>, DatabaseError> {
        use std::fs;

        let mut studies = HashMap::new();
        for entry in fs::read_dir("states")? {
            if let Ok(entry) = entry {
                if let Some(f) = entry.file_name().to_str() {
                    if f.ends_with(".json") {
                        if let Ok(uuid) = Uuid::parse_str(&f[..36]) {
                            let filename = format!("states/{}", f);
                            if let Ok(data) = fs::read(filename) {
                                let data = String::from_utf8(data)?;
                                let study: Study = serde_json::from_str(&data)?;
                                studies.insert(uuid.to_hyphenated().to_string(), study);
                            }
                        }
                    }
                }
            }
        }

        Ok(studies)
    }

    pub fn get_responses(id: &str) -> Result<Vec<u8>, DatabaseError> {
        use std::fs;

        let filename = format!("states/{}.dat", id);
        Ok(fs::read(filename)?)
    }

    pub fn persist(studies: &mut HashMap<String, Study>) {
        use std::fs;
        use std::fs::OpenOptions;

        fs::create_dir_all("states").expect("cannot create states directory");

        for (id, study) in studies.iter_mut() {
            if study.dirty {
                study.dirty = false;

                if let Ok(uuid) = Uuid::parse_str(&id) {
                    while !study.responses.is_empty() {
                        let data = study.responses.remove(0);
                        let filename = format!("states/{}.dat", uuid.to_hyphenated().to_string());
                        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&filename) {
                            let _ = file.write_all(&data);
                        }
                    }

                    if let Ok(json) = serde_json::to_string(study) {
                        let filename = format!("states/{}.json", uuid.to_hyphenated().to_string());
                        let _ = fs::write(filename, json.as_bytes());
                    }
                }
            }
        }
    }
}
