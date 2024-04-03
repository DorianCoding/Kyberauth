use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
    Key // Or `Aes128Gcm`
};
use hex;
use pqc_kyber::*;
use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use zeroize::Zeroize;
const NONCESIZE: usize = 96 / 8;
const MAXSIZE: usize = 10000;
#[derive(Debug, Zeroize)]
pub struct Connection {
    #[zeroize(skip)]
    socket: TcpStream,
    #[zeroize(skip)]
    pub peer_addr: SocketAddr,
    pub pubkey: String,
    aeskey: [u8; KYBER_SSBYTES],
}
impl Connection {
    pub async fn clean(&mut self) -> io::Result<()> {
        let socket = &mut self.socket;
        socket.flush().await?;
        socket.shutdown().await?;
        Ok(())
    }
    pub fn new(
        socket: TcpStream,
        peer_addr: SocketAddr,
        pubkey: String,
        aeskey: [u8; KYBER_SSBYTES],
    ) -> Self {
        Connection {
            socket: socket,
            peer_addr: peer_addr,
            pubkey: pubkey,
            aeskey: aeskey,
        }
    }
    pub async fn senddata(&mut self, text: &[u8]) -> io::Result<()> {
        let vec = Vec::from(text);
        let cipher = self.encryptdata(vec).unwrap();
        self.socket.writable().await?;
        self.socket.write_all(&cipher).await?;
        self.socket.flush().await?;
        Ok(())
    }
    pub async fn receivedata(&mut self) -> io::Result<Vec<u8>> {
        let mut vec = Vec::new();
        vec.resize(MAXSIZE, 0);
        self.socket.readable().await?;
        let size = self.socket.read(&mut vec).await?;
        vec.resize(size, 0);
        println!("Vec is {}", hex::encode(&vec));
        let cipher = self.decryptdata(vec).unwrap();
        Ok(cipher)
    }
    pub fn encryptdata(&self, mut input: Vec<u8>) -> Result<Vec<u8>, aes_gcm::Error> {
        // Alternatively, the key can be transformed directly from a byte slice
        // (panicks on length mismatch):
        if input.len() > MAXSIZE {
            return Ok(Vec::new());
        }
        let key = Key::<Aes256Gcm>::from_slice(&self.aeskey);

        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
        let mut ciphertext = cipher.encrypt(&nonce, input.as_ref())?;
        let mut finale: Vec<u8> = Vec::new();
        finale.extend_from_slice(nonce.as_ref());
        finale.append(&mut ciphertext);
        input.zeroize();
        return Ok(finale);
    }
    pub fn decryptdata(&self, input: Vec<u8>) -> Result<Vec<u8>, aes_gcm::Error> {
        if input.len() > MAXSIZE || input.len() < NONCESIZE {
            return Ok(Vec::new());
        }
        let key = Key::<Aes256Gcm>::from_slice(&self.aeskey);
        let cipher = Aes256Gcm::new(&key);
        let nonce = &input.as_slice()[..NONCESIZE];
        let input: &[u8] = &input.as_slice()[NONCESIZE..];
        let plaintext = cipher.decrypt(nonce.as_ref().into(), input.as_ref())?;
        return Ok(plaintext);
    }
}
