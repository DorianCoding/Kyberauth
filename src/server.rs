use pqc_kyber::*;
use sha3::{Digest, Sha3_256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use std::fs;
use std::{
    net::SocketAddr,
    io::{self, Error, ErrorKind}
};
async fn keyhandshake(socket: &mut TcpStream, key: &Keypair) -> io::Result<Vec<u8>> {
    let _ = socket.set_nodelay(true);
    socket.readable().await?;
    let mut pubkey: Vec<u8> = Vec::with_capacity(KYBER_PUBLICKEYBYTES);
    pubkey.clear();
    pubkey.resize(KYBER_PUBLICKEYBYTES, 0);
    let _ = socket.read_exact(&mut pubkey).await?;
    //The key was read
    socket.writable().await?;
    socket.write_all(&key.public).await?;
    socket.flush().await?;
    Ok(pubkey)
}
async fn checkkeys(
    socket: &mut TcpStream,
    key: &Keypair,
    pubkey: Vec<u8>,
) -> io::Result<[u8; KYBER_SSBYTES]> {
    let _ = socket.set_nodelay(true);
    socket.readable().await?;
    let mut bob = Ake::new();
    let mut client_init: Vec<u8> = Vec::with_capacity(AKE_INIT_BYTES);
    client_init.clear();
    client_init.resize(AKE_INIT_BYTES, 0);
    let _ = socket.read_exact(&mut client_init).await?;
    //The key was read
    if pubkey.len() != KYBER_PUBLICKEYBYTES {
        return Err(io::Error::from(ErrorKind::InvalidInput));
    }
    let pubkey: [u8; KYBER_PUBLICKEYBYTES] = pubkey[..KYBER_PUBLICKEYBYTES]
        .try_into()
        .unwrap();
    if client_init.len() != AKE_INIT_BYTES {
        return Err(io::Error::from(ErrorKind::InvalidInput));
    }
    let client_init: [u8; AKE_INIT_BYTES] = client_init[..AKE_INIT_BYTES]
        .try_into()
        .unwrap();
    let mut rng = rand::thread_rng();
    let server_send = bob
        .server_receive(client_init, &pubkey, &key.secret, &mut rng);
    if server_send.is_err() {
        return Err(io::Error::from(ErrorKind::InvalidInput));
    }
    socket.writable().await?;
    socket.write_all(&server_send.unwrap()).await?;
    socket.flush().await?;
    Ok(bob.shared_secret)
}
/// Verify peer key is allowed in authorized_keys
pub fn verifypubkey(pubkey: &[u8]) -> bool {
    let mut read = fs::read_to_string("authorized_keys").unwrap_or_default();
    read = String::from(read.trim());
    if read.len() == 0 {
        return false;
    }
    // create a SHA3-256 object
    let mut hasher = Sha3_256::new();

    // write input message
    hasher.update(&pubkey);

    // read hash digest
    let result = hex::encode(hasher.finalize());
    for line in read.lines() {
        if line.split(" ").collect::<Vec<_>>()[0].trim() == result {
            return true;
        }
    }
    false
}
/// Start to listen to the socket addr
pub async fn startlistener(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = TcpSocket::new_v4()?;
    if cfg!(unix) {
        socket.set_reuseport(false)?;
    }
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    let listener = socket.listen(1024)?;
    Ok(listener)
}
/// Accept incoming connection, check pub key and generate an encrypted channel
pub async fn listener(key: &Keypair, listener: TcpListener, forceyes: bool) -> io::Result<crate::aes::Connection> {
    loop {
        let (mut socket, _) = listener.accept().await?;
        let peer_addr=socket.peer_addr();
        if peer_addr.is_err() {
            return Err(io::Error::from(io::ErrorKind::ConnectionAborted));
        }
        let peer_addr = peer_addr.unwrap();
        let pubkey = keyhandshake(&mut socket, key).await?;
        if !forceyes && !verifypubkey(&pubkey) {
            socket.shutdown().await?;
            return Err(Error::new(ErrorKind::InvalidData,"Key not found"));
        }
        let hexpub=hex::encode(pubkey.clone());
        let sharedsecret = checkkeys(&mut socket, key, pubkey).await?;
        let elem=crate::aes::Connection::new(socket, peer_addr, hexpub, sharedsecret);
        return Ok(elem);
    }
}
