sgx:
	cargo build --release --target x86_64-fortanix-unknown-sgx
	ftxsgx-elf2sgxs target/x86_64-fortanix-unknown-sgx/release/peqes-server --heap-size 0x20000000 --stack-size 0x2000000 --threads 10

non-sgx:
	cargo build --release

clean:
	cargo clean

all:	sgx non-sgx
