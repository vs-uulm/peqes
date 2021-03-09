use tokio::io::{AsyncRead, AsyncWrite};
use std::io::{Read, Result as IoResult, Write};
use std::fs;
use std::fs::OpenOptions;
use std::convert::TryInto;
use uuid::Uuid;
use std::task::{Poll, Context};
use std::pin::Pin;

struct DatabaseServiceState {
    wb: Vec<u8>,
    rb: Vec<u8>
}

impl DatabaseServiceState {
    pub fn get(&self, index: usize) -> IoResult<&u8> {
        match self.wb.get(index) {
            Some(b) => Ok(b),
            None => Err(std::io::Error::new(std::io::ErrorKind::Other, "EOF"))
        }
    }

    pub fn has(&self, count: usize) -> IoResult<()> {
        if self.wb.len() >= count {
            Ok(())
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "EOF"))
        }
    }

    pub fn remove(&mut self, count: usize) {
        // panics if the buffer contains not enough bytes to remove
        for _ in 0..count {
            self.wb.remove(0);
        }
    }

    pub fn send(&mut self, data: &[u8]) {
        self.rb.extend_from_slice(data);
    }
}

pub struct DatabaseService {
    state: DatabaseServiceState
}

impl DatabaseService {
    pub fn new() -> DatabaseService {
        fs::create_dir_all("states").expect("cannot create states directory");
        DatabaseService {
            state: DatabaseServiceState { wb: vec![], rb: vec![] }
        }
    }

    fn parse(&mut self) -> IoResult<()> {
	let state = &mut self.state;
        while state.wb.len() > 0 {
            match state.get(0)? {
                0 => {
                    // read
                    state.remove(1);

                    let mut files = Vec::new();

                    for entry in fs::read_dir("states")? {
                        if let Ok(entry) = entry {
                            if let Some(f) = entry.file_name().to_str() {
                                if f.ends_with(".json") {
                                    files.push(f.to_string());
                                }
                            }
                        }
                    }

                    let mut count = files.len();
                    state.send(&usize::to_be_bytes(count));
                    for file in files {
                        if let Ok(uuid) = Uuid::parse_str(&file[..36]) {
                            let filename = format!("states/{}", file);
                            if let Ok(data) = fs::read(filename) {
                                state.send(uuid.as_bytes());
                                state.send(&usize::to_be_bytes(data.len()));
                                state.send(&data);
                                count -= 1;
                            }
                        }
                    }

                    for _ in 0..count {
                        // corrupted file?
                        state.send(&[0u8; 16 + 8]);
                    }
                },

                1 => {
                    // write
                    state.has(25)?;
                    let uuid = Uuid::from_slice(&state.wb[1..17]).unwrap();
                    let size: [u8; 8] = state.wb[17..25].try_into().unwrap();
                    let size = usize::from_be_bytes(size);

                    state.has(25 + size)?;
                    let payload = &state.wb[25..(25 + size)];

                    let filename = format!("states/{}.json", uuid.to_hyphenated().to_string());
                    fs::write(filename, &payload)?;
                    state.remove(25 + size);
                },

                2 => {
                    // append
                    state.has(25)?;
                    let uuid = Uuid::from_slice(&state.wb[1..17]).unwrap();
                    let size: [u8; 8] = state.wb[17..25].try_into().unwrap();
                    let size = usize::from_be_bytes(size);

                    state.has(25 + size)?;
                    let payload = &state.wb[25..(25 + size)];

                    let filename = format!("states/{}.dat", uuid.to_hyphenated().to_string());
                    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&filename) {
                        file.write_all(&payload)?;
                        state.remove(25 + size);
                    }
                },

                3 => {
                    // get
                    state.has(17)?;
                    let uuid = Uuid::from_slice(&state.wb[1..17]).unwrap();
                    let filename = format!("states/{}.dat", uuid.to_hyphenated().to_string());
                    if let Ok(data) = fs::read(filename) {
                        state.send(&usize::to_be_bytes(data.len()));
                        state.send(&data);
                    } else {
                        state.send(&[0u8; 8]);
                    }
                    state.remove(17);
                },

                _ => panic!("protocol error")
            }
        }

        Ok(())
    }
}

impl Read for DatabaseService {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let count = usize::min(buf.len(), self.state.rb.len());

        for i in 0..count {
            buf[i] = self.state.rb.remove(0);
        }

        Ok(count)
    }
}

impl Write for DatabaseService {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.state.wb.extend_from_slice(&buf);
        let _ = self.parse();

        Ok(buf.len())
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

impl AsyncRead for DatabaseService {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        Poll::Ready(self.get_mut().read(buf))
    }
}

impl AsyncWrite for DatabaseService {
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

