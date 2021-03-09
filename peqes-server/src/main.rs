#![feature(stdsimd)]

extern crate tiny_http;
extern crate base64;
extern crate ring;
extern crate hex;
extern crate uuid;
extern crate serde;
extern crate quickjs_rs;
extern crate aes_gcm;
#[macro_use] extern crate serde_json;
#[macro_use] extern crate http_router;

mod attestation;
use attestation::RaContext;

mod crypto;

mod studies;
use crate::studies::{Study, StudyStatus};

mod database;
use crate::database::Database;

use std::rc::Rc;
use std::cell::RefCell;
use std::str;
use std::collections::HashMap;

use tiny_http::{Server, Request, Response, Method};

use uuid::Uuid;

type ServerResponse = tiny_http::Response<std::io::Cursor<Vec<u8>>>;
pub struct RequestContext {
    body: Option<serde_json::Value>,
    studies: Rc<RefCell<HashMap<String, Study>>>,
    attestations: Rc<RefCell<HashMap<String, RaContext>>>
}

impl RequestContext {
    fn borrow_studies(&self) -> impl std::ops::Deref<Target = HashMap<String, Study>> + '_ {
        self.studies.borrow()
    }

    fn borrow_studies_mut(&self) -> impl std::ops::DerefMut<Target = HashMap<String, Study>> + '_ {
        self.studies.borrow_mut()
    }

    fn borrow_attestations_mut(&self) -> impl std::ops::DerefMut<Target = HashMap<String, RaContext>> + '_ {
        self.attestations.borrow_mut()
    }
}


impl Drop for RequestContext {
    fn drop(&mut self) {
        Database::persist(&mut self.borrow_studies_mut());
    }
}

pub struct ServerState {
    studies: Rc<RefCell<HashMap<String, Study>>>,
    attestations: Rc<RefCell<HashMap<String, RaContext>>>
}

impl ServerState {
    pub fn new() -> ServerState {
        let studies = Database::restore().unwrap_or(HashMap::new());
        let attestations = HashMap::new();

        ServerState {
            studies: Rc::new(RefCell::new(studies)),
            attestations: Rc::new(RefCell::new(attestations))
        }
    }

    pub fn create_request_context(&self, value: Option<serde_json::Value>) -> RequestContext {
        RequestContext {
            body: value,
            studies: Rc::clone(&self.studies),
            attestations: Rc::clone(&self.attestations),
        }
    }
}

fn get_content_type(request: &Request) -> &str {
    for header in request.headers() {
        if header.field == "Content-Type".parse().unwrap() {
            return header.value.as_str();
        }
    }

    return "";
}

fn parse_json_body(request: &mut tiny_http::Request) -> Result<serde_json::Value, ()> {
    let content_type = get_content_type(&request);
    if !content_type.to_string().starts_with("application/json") {
        Err(())
    } else {
        let mut content = String::new();
        match request.as_reader().read_to_string(&mut content) {
            Err(_) => Err(()),
            Ok(_) => {
                match content.parse() {
                    Err(_) => Err(()),
                    Ok(json) => Ok(json)
                }
            }
        }
    }
}

pub fn get_studies(context: &RequestContext) -> ServerResponse {
    let mut response = serde_json::map::Map::new();

    for (id, study) in context.borrow_studies().iter() {
        response.insert(id.to_string(), json!({
            "name": study.name,
            "description": study.description,
            "status": study.status
        }));
    }

    let response = serde_json::value::Value::from(response);
    Response::from_string(&response.to_string()).with_status_code(200)
}

pub fn get_study(context: &RequestContext, id: String) -> ServerResponse {
    match context.borrow_studies().get(&id) {
        None => not_found(),

        Some(study) => {
            let response = match study.status {
                StudyStatus::New => study.to_signing_request(),
                _ => study.to_json().to_string()
            };

            Response::from_string(response).with_status_code(200)
        }
    }
}

pub fn approve_study(context: &RequestContext, id: String) -> ServerResponse {
    let mut studies = context.borrow_studies_mut();
    let json = context.body.as_ref().unwrap();

    let study = match studies.get_mut(&id) {
        None => return not_found(),
        Some(study) => study
    };

    let (pk, cert) = match (json.get("pk"), json.get("cert")) {
        (Some(serde_json::Value::String(pk)), Some(serde_json::Value::String(cert))) => (
            base64::decode(pk).unwrap(),
            base64::decode(cert).unwrap()
        ),
        _ => return bad_request()
    };

    match study.add_certificate(&pk, cert) {
        Err(_) => bad_request(),
        Ok(_) => {
            Response::from_string(json!({ "ok": true }).to_string()).with_status_code(200)
        }
    }
}

pub fn add_study(context: &RequestContext) -> ServerResponse {
    let mut studies = context.borrow_studies_mut();

    let study = match Study::from_json(context.body.as_ref().unwrap()) {
        Err(_) => return bad_request(),
        Ok(study) => study
    };

    let id = Uuid::new_v4().to_hyphenated().to_string();
    studies.insert(id.to_string(), study);
    let response = json!({ "ok": true, "id": id });
    Response::from_string(&response.to_string()).with_status_code(201)
}

pub fn initiate_response(context: &RequestContext, id: String) -> ServerResponse {
    let mut studies = context.borrow_studies_mut();
    let study = match studies.get_mut(&id) {
        None => return not_found(),
        Some(study) => study
    };

    match study.initiate_response() {
        Err(_) => internal_server_error(),

        Ok((id, pk, signature)) => {
            let response = json!({
                "ok": true,
                "id": id,
                "pk": pk,
                "signature": signature
            });

            Response::from_string(&response.to_string()).with_status_code(201)
        }
    }
}

pub fn submit_response(context: &RequestContext, id: String, response_id: String) -> ServerResponse {
    let mut studies = context.borrow_studies_mut();
    let json = context.body.as_ref().unwrap();

    match (json.get("pk"), json.get("response"), json.get("nonce")) {
        (Some(serde_json::Value::String(pk)), Some(serde_json::Value::String(response)), Some(serde_json::Value::String(nonce))) => {
            let response = base64::decode(response).unwrap();
            let nonce = base64::decode(nonce).unwrap();
            let pk = base64::decode(pk).unwrap();

            match studies.get_mut(&id) {
                None => not_found(),

                Some(study) => {
                    match study.submit_response(&response_id, &pk, &response, &nonce) {
                        Err(_) => bad_request(),
                        Ok(_) => Response::from_string(json!({ "ok": true }).to_string()).with_status_code(201)
                    }
                }
            }
        },

        _ => bad_request()
    }
}

pub fn complete_study(context: &RequestContext, id: String) -> ServerResponse {
    let mut studies = context.borrow_studies_mut();
    let json = context.body.as_ref().unwrap();

    let study = match studies.get_mut(&id) {
        None => return not_found(),
        Some(study) => study
    };

    let auth = match json.get("auth") {
        Some(serde_json::Value::String(auth)) => auth,
        _ => return forbidden()
    };

    if let Err(_) = study.auth_researcher(&auth) {
        return forbidden();
    }

    let responses = match Database::get_responses(&id) {
        Err(_) => return not_found(),
        Ok(responses) => responses
    };

    let res = match study.complete_study(responses) {
        Err(_) => return internal_server_error(),
        Ok(res) => res
    };

    Response::from_string(res).with_status_code(200)
}

pub fn default_route(_context: &RequestContext) -> ServerResponse {
    not_found()
}

pub fn not_found() -> ServerResponse {
    Response::from_string("Not Found").with_status_code(404)
}

pub fn forbidden() -> ServerResponse {
    Response::from_string("Forbidden").with_status_code(403)
}

pub fn bad_request() -> ServerResponse {
    Response::from_string("Bad Request").with_status_code(400)
}

pub fn precondition_failed() -> ServerResponse {
    Response::from_string("Precondition Failed").with_status_code(412)
}

pub fn internal_server_error() -> ServerResponse {
    Response::from_string("Internal Server Error").with_status_code(500)
}

pub const SP_VKEY_PEM: &str = "\
-----BEGIN RSA PUBLIC KEY-----\n
MIIBCgKCAQEAvtc94gzwX0KeL1HJVh6XdHPXXA4PYE+ClqWUvxp5ts1/nLQzJVcy\
1SHMGaPUCr+IZJBeWapkFpgnJnw7YzdQ2kA8k6GiN/k8hlQMWXA2nE0LDeOHX8i7\
fc31lWy5nHdAXj7SfC/YV5RC/yhkJ2cYNMB15VPRHGQRukdVmvHUFunxwfkHq5mM\
xWWAWO5Km490NCWP7CqBH6ezGm5jUhzYT/n5y5EaVpqwKVE1uYA//L4dFSE7aDzD\
CDb50B9uqPaEyKHwc2taLiSPvQjDQE3BpKTDOqsVnojd9br1vYW/uemYnnlOJbSr\
L7pYuPODmV02by5r+7hgXFQkTADwFQBCmwIDAQAB\n\
-----END RSA PUBLIC KEY-----\
";

pub fn approve_study_init(context: &RequestContext, id: String) -> ServerResponse {
    if !context.borrow_studies().contains_key(&id) {
        return not_found();
    }

    let ctx = RaContext::init(SP_VKEY_PEM).unwrap();
    let res = ctx.get_msg_01();
    context.borrow_attestations_mut().insert(ctx.get_id(), ctx);
    Response::from_string(res).with_status_code(200)
}

pub fn approve_study_attest(context: &RequestContext, id: String, attestation: String) -> ServerResponse {
    if !context.borrow_studies().contains_key(&id) {
        return not_found();
    }

    let json = context.body.as_ref().unwrap();
    match context.borrow_attestations_mut().get_mut(&attestation) {
        None => not_found(),

        Some(ctx) => match ctx.process_msg_2(json) {
            Err(_) => internal_server_error(),
            Ok(res) => Response::from_string(res).with_status_code(200)
        }
    }
}

pub fn approve_study_finish(context: &RequestContext, id: String, attestation: String) -> ServerResponse {
    let studies = context.borrow_studies();
    let json = context.body.as_ref().unwrap();

    let study = match studies.get(&id) {
        None => return not_found(),
        Some(study) => study
    };

    let (challenge, nonce) = match (json.get("challenge"), json.get("nonce")) {
        (Some(serde_json::Value::String(challenge)), Some(serde_json::Value::String(nonce))) => (challenge, nonce),
        _ => return bad_request()
    };

    let (challenge, nonce) = match (base64::decode(challenge), base64::decode(nonce)) {
        (Ok(challenge), Ok(nonce)) => (challenge, nonce),
        _ => return bad_request()
    };

    let kdk = match context.borrow_attestations_mut().remove(&attestation) {
        None => return not_found(),
        Some(ctx) => match ctx.complete_attestation() {
            Err(_) => return internal_server_error(),
            Ok(kdk) => kdk
        }
    };

    let challenge = match crypto::decrypt(&kdk, &challenge, &nonce) {
        Err(_) => return internal_server_error(),
        Ok(challenge) => challenge
    };

    let signature = match study.sign_response(&challenge) {
        Err(_) => return internal_server_error(),
        Ok(signature) => signature
    };

    let hmac = match crypto::hmac(&kdk, &signature) {
        Err(_) => return internal_server_error(),
        Ok(hmac) => hmac
    };

    let response = json!({
        "response": base64::encode(&signature[..]),
        "auth": base64::encode(&hmac[..]),
    }).to_string();

    Response::from_string(response).with_status_code(200)
}

fn main() {
    let router = router!(
        GET /studies => get_studies,
        POST /studies => add_study,

        GET /studies/{id: String} => get_study,
        PUT /studies/{id: String} => approve_study,

        GET /studies/{id: String}/approve => approve_study_init,
        PUT /studies/{id: String}/approve/{attestation: String} => approve_study_attest,
        POST /studies/{id: String}/approve/{attestation: String} => approve_study_finish,

        POST /studies/{id: String} => initiate_response,
        PUT /studies/{id: String}/{response: String} => submit_response,

        POST /studies/{id: String}/complete => complete_study,

        _ => default_route,
    );

    let server = Server::http("0.0.0.0:3001").unwrap();
    let state = ServerState::new();

    for mut request in server.incoming_requests() {
        let path: String = request.url().into();

        println!("{:?} {:?}", request.method(), &path);
        let response = match request.method() {
            &Method::Get => {
                router(
                    state.create_request_context(None),
                    http_router::Method::GET,
                    &path
                )
            },

            &Method::Post => {
                match parse_json_body(&mut request) {
                    Err(_) => bad_request(),
                    Ok(json) => router(
                        state.create_request_context(Some(json)),
                        http_router::Method::POST,
                        &path
                    )
                }
            },

            &Method::Put => {
                match parse_json_body(&mut request) {
                    Err(_) => bad_request(),
                    Ok(json) => router(
                        state.create_request_context(Some(json)),
                        http_router::Method::PUT,
                        &path
                    )
                }
            }

            _ => Response::from_string("Method Not Allowed").with_status_code(405)
        };

        let _ = request.respond(response);
    }
}
