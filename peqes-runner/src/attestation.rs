use tokio::io::{AsyncRead, AsyncWrite};
use std::io::{Read, Result as IoResult, Write};
use aesm_client::{AesmClient, QuoteInfo};
use sgx_isa::Report;
use std::task::{Poll, Context};
use std::pin::Pin;

struct AttestationServiceState {
    aesm_client: AesmClient,
    quote_info: QuoteInfo,
    wb: Vec<u8>,
    rb: Vec<u8>
}

pub struct AttestationService {
    state: AttestationServiceState
}

impl AttestationService {
    pub fn new() -> aesm_client::Result<AttestationService> {
        let aesm_client = AesmClient::new();
        let quote_info = aesm_client.init_quote()?;

        let mut rb = Vec::from(quote_info.gid());
        rb.extend_from_slice(quote_info.target_info());

        Ok (AttestationService {
            state: AttestationServiceState {
                aesm_client,
                quote_info,
                wb: vec![],
                rb: rb
            }
        })
    }
}

impl Read for AttestationService {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let count = usize::min(buf.len(), self.state.rb.len());

        for i in 0..count {
            buf[i] = self.state.rb.remove(0);
        }

        Ok(count)
    }
}

impl Write for AttestationService {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        let state = &mut self.state;

        state.wb.extend_from_slice(&buf); 

        if state.wb.len() >= std::mem::size_of::<usize>() {
            let mut sigrl_len: [u8; std::mem::size_of::<usize>()] = [0; std::mem::size_of::<usize>()];
            sigrl_len.copy_from_slice(&state.wb[0..std::mem::size_of::<usize>()]);
            let sigrl_len = usize::from_be_bytes(sigrl_len);

            if state.wb.len() == std::mem::size_of::<usize>() + sigrl_len + 16 + Report::UNPADDED_SIZE {
                let mut sigrl = vec![0u8; sigrl_len];
                sigrl.copy_from_slice(&state.wb[std::mem::size_of::<usize>()..std::mem::size_of::<usize>()+sigrl_len]);
                let mut spid = vec![0u8; 16];
                spid.copy_from_slice(&state.wb[std::mem::size_of::<usize>()+sigrl_len..std::mem::size_of::<usize>()+sigrl_len+16]);
                let mut report = vec![0u8; Report::UNPADDED_SIZE];
                report.copy_from_slice(&state.wb[std::mem::size_of::<usize>()+sigrl_len+16..std::mem::size_of::<usize>()+sigrl_len+16+Report::UNPADDED_SIZE]);

                match state.aesm_client.get_quote(&state.quote_info, report, spid, sigrl) {
                    Err(_) => println!("todo"),
                    Ok(quote) => {
                        state.rb.extend_from_slice(&quote.quote()); 
                        state.rb.extend_from_slice(&quote.qe_report()); 
                    }
                };
            }
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

impl AsyncRead for AttestationService {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        Poll::Ready(self.get_mut().read(buf))
    }
}

impl AsyncWrite for AttestationService {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        Poll::Ready(self.get_mut().write(&buf))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Poll::Ready(Ok(()))
    }
}

