# Kyberauth
[![License](https://img.shields.io/crates/l/pqc_kyber)](https://github.com/DorianCoding/Kyberauth/blob/main/LICENSE-MIT)
[![dependency status](https://deps.rs/repo/github/DorianCoding/Kyberauth/status.svg)](https://deps.rs/repo/github/DorianCoding/Kyberauth)

A rust implementation of the Kyber algorithm, a KEM standardised by the NIST Post-Quantum Standardization Project, combined with a verification of keys and use of encapsulated key in AES-GCM in TCP sockets.

This library:
* Is fully written in Rust.
* Is compatible for Windows, Unix.
* Compatible with i383 and x86_64 architectures.


Please read the [**security considerations**](#security-considerations) before use.

**Minimum Supported Rust Version: 1.73.0**

---

## Installation

```shell
git clone "https://github.com/DorianCoding/Kyberauth.git"
```

or on Cargo.toml

```rust
[dependencies]
regex = { git = "https://github.com/DorianCoding/Kyberauth.git" }
```

## Usage 

```rust
use kyberauth::*;
```
---
### KEM generation

```rust
fn createkeys() -> Result<KeyPair, KyberError> {
    let mut rng = rand::thread_rng();
    let mut keys = keypair(&mut rng)?;
    Ok(keys)
}
```
### Server and client interface

#### Client

```rust
async fn server() -> Result<(), KyberError> {
    let mut rng = rand::thread_rng();
    let keys = keypair(&mut rng)?;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 43050);
    let listener = server::startlistener(addr).await;
    let listener = match listener {
        Ok(listener) => listener,
        Err(_) => {
            return Err(KyberError::InvalidInput);
        }
    };
    let _ = match server::listener(&keys, listener, false).await {
        Ok(mut elem) => {
            elem.senddata(TEST.as_bytes()).await.unwrap();
            return Ok(());
        }
        Err(e) => {
            return Err(KyberError::InvalidInput);
        }
    };
}
```
#### Server

```rust
async fn client() -> Result<(), KyberError> {
    let mut rng = rand::thread_rng();
    let keys = keypair(&mut rng)?;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 43050);
    let _ = match client::connecter(&keys, addr).await {
        Ok(mut elem) => {
            let text = elem.receivedata().await.unwrap();
            if text.len() == 0 {
                eprintln!("Invalid response!");
                return Err(KyberError::InvalidInput);
            }
            let info = String::from_utf8(text).unwrap();
            assert_eq!(info, TEST);
            println!("The peer is {} and public key is {}",elem.getpeer(),String::from_utf8(elem.getpeerkey(false).unwrap()).unwrap());
            ()
        }
        Err(e) => {
            eprintln!("Error is {}", e);
            return Err(KyberError::InvalidInput);
        }
    };
    Ok(())
}
```

---
## Testing

There is some tests to verify that the library is working fine, you can try them using :

```bash
# This example runs the tests
cargo test
```

---

## Security Considerations 

This library is using some not-verified cryptographic crates. It also uses alone quantum-resistant algorithms based on lattices. It should be used with another KEM that is not implemented here.

Therefore, this library should not be used for safety uses and is given without any warranty.

---

## About

This library uses [KYBER library](https://github.com/Argyle-Software/kyber#about) in Rust, as well as [AES-GCM](https://docs.rs/aes-gcm/latest/aes_gcm/) as cryptographic algorithms.

## Contributing 

Contributions are welcome. Feel free to pull requests or to share any ideas.

## License

This library is shared under Apache2-0 OR MIT, you can use the one you please.