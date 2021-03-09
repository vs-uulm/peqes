extern crate aesm_client;
extern crate enclave_runner;
extern crate sgxs_loaders;
extern crate failure;
extern crate futures;
extern crate tokio;

mod database;
use crate::database::DatabaseService;

mod attestation;
use crate::attestation::AttestationService;

use aesm_client::AesmClient;
use enclave_runner::EnclaveBuilder;
use enclave_runner::usercalls::{AsyncStream, UsercallExtension};
use failure::{Error, ResultExt};
use std::io::Result as IoResult;
use sgxs_loaders::isgx::Device as IsgxDevice;
use futures::future::Future;
use futures::future::ok;

#[derive(Debug)]
struct ExternalService;
impl UsercallExtension for ExternalService {
    fn connect_stream<'future>(
        &'future self,
        addr: &'future str,
        _: Option<&'future mut String>,
        _: Option<&'future mut String>,
    ) -> std::pin::Pin<Box<dyn Future<Output = IoResult<Option<Box<dyn AsyncStream>>>> + 'future>> {
        Box::pin(ok(match &addr[..] {
            "attestation" => match AttestationService::new() {
                Err(_) => None,
                Ok(stream) => {
                    let stream: Box<dyn AsyncStream> = Box::new(stream);
                    Some(stream)
                }
            },

            "database" => {
                let stream: Box<dyn AsyncStream> = Box::new(DatabaseService::new());
                Some(stream)
            },

            _ => None
        }))
    }
}

fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <path_to_sgxs_file>", args[0]);
        std::process::exit(-1)
    }

    let file = args[1].to_owned();

    let mut device = IsgxDevice::new()
        .context("While opening SGX device")?
        .einittoken_provider(AesmClient::new())
        .build();

    let mut enclave_builder = EnclaveBuilder::new(file.as_ref());
    enclave_builder.dummy_signature();
    enclave_builder.usercall_extension(ExternalService);

    let enclave = enclave_builder
        .build(&mut device)
        .context("While loading SGX enclave")?;

    enclave.run().map_err(|e| {
        eprintln!("Error while executing SGX enclave.\n{}", e);
        std::process::exit(-1)
    })
}

