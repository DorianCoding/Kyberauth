use safe_pqc_kyber::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{ TcpSocket, TcpStream};
use std::io::ErrorKind;
use std::{
    io,
    net::SocketAddr,
};

async fn keyhandshake(socket: &mut TcpStream, key: &Keypair) -> io::Result<Vec<u8>> {
    let _ = socket.set_nodelay(true);
    //The key is sent
    socket.writable().await?;
    socket.write_all(&key.public).await?;
    socket.flush().await?;
    socket.readable().await?;
    let mut pubkey: Vec<u8> = Vec::with_capacity(KYBER_PUBLICKEYBYTES);
    pubkey.clear();
    pubkey.resize(KYBER_PUBLICKEYBYTES, 0);
    let _ = socket.read_exact(&mut pubkey).await?;
    //The key was read
    Ok(pubkey)
}
async fn checkkeys<T>(
    socket: &mut TcpStream,
    key: &Keypair,
    pubkey: T,
) -> io::Result<[u8; KYBER_SSBYTES]> where T: AsRef<[u8]> {
    let pubkey = pubkey.as_ref();
    let _ = socket.set_nodelay(true);
    socket.writable().await?;
    let mut rng = rand::thread_rng();
    let mut alice = Ake::new();
    let pubkey: [u8; KYBER_PUBLICKEYBYTES] = pubkey[..KYBER_PUBLICKEYBYTES]
        .try_into().unwrap_or([0;KYBER_PUBLICKEYBYTES]);
    let client_init = alice.client_init(&pubkey, &mut rng);
    if pubkey == [0;KYBER_PUBLICKEYBYTES] {
        return Err(io::Error::from(ErrorKind::InvalidInput));
    }
    socket.write_all(&client_init).await?;
    socket.flush().await?;
    socket.readable().await?;
    let mut server_answer: Vec<u8> = Vec::with_capacity(AKE_RESPONSE_BYTES);
    server_answer.clear();
    server_answer.resize(AKE_RESPONSE_BYTES, 0);
    let _ = socket.read_exact(&mut server_answer).await?;
    //The key was read
    let server_answer: [u8; AKE_RESPONSE_BYTES] = server_answer[..AKE_RESPONSE_BYTES]
        .try_into()
        .unwrap_or([0;AKE_RESPONSE_BYTES]);
    let result = alice
        .client_confirm(server_answer, &key.secret);
    if server_answer == [0;AKE_RESPONSE_BYTES] || result.is_err() {
        return Err(io::Error::from(ErrorKind::InvalidInput));
    }
    Ok(alice.shared_secret)
}

pub async fn connecter(key: &Keypair, addr: SocketAddr) -> io::Result<crate::aes::Connection> {

    let socket = TcpSocket::new_v4()?;
    if cfg!(unix) {
        socket.set_reuseport(false)?;
    }
    socket.set_reuseaddr(false)?;
    let mut stream: TcpStream = socket.connect(addr).await?; //TODO: Implements a timeout
    let pubkey = keyhandshake(&mut stream, key).await?;
    let hexpub=hex::encode(pubkey.clone());
    let sharedsecret = checkkeys(&mut stream, key, &pubkey).await?;
    let peer_addr = stream.peer_addr();
    if peer_addr.is_err() {
        return Err(io::Error::from(io::ErrorKind::ConnectionAborted));
    }
    let elem = crate::aes::Connection::new(stream, peer_addr.unwrap(), hexpub, sharedsecret);
    Ok(elem)
}
