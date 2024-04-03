use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
    Key // Or `Aes128Gcm`use kyberauth::printkeystofile;
};
use hex;
use pqc_kyber::*;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
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
    /// Flush and shutdown the socket
    pub async fn clean(&mut self) -> io::Result<()> {
        let socket = &mut self.socket;
        socket.flush().await?;
        socket.shutdown().await?;
        Ok(())
    }
    /// Create a new connection with pubkey and to transmit aeskey. AES key is hidden and cannot be retrieved for security reasons.
    pub(crate) fn new(
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
    /// Get peer public key
    pub fn getpeerkey(&self,hex: bool) -> Result<Vec<u8>,hex::FromHexError> {
        if hex {
            Ok(self.pubkey.clone().into_bytes())
        } else {
            Ok(hex::decode(self.pubkey.clone())?.to_vec())
        }
    }
    pub fn getsocket(self) -> TcpStream {
        self.socket
    }
    pub fn getpeer(&self) -> SocketAddr {
        self.peer_addr
    }
    /// Encrypt data via AES key into the connection, might return an error.
    pub async fn senddata(&mut self, text: &[u8]) -> io::Result<()> {
        let vec = Vec::from(text);
        let cipher = self.encryptdata(vec);
        if cipher.is_err() {
            return Err(io::Error::from(ErrorKind::InvalidData));
        }
        let cipher = cipher.unwrap();
        self.socket.writable().await?;
        self.socket.write_all(&cipher).await?;
        self.socket.flush().await?;
        Ok(())
    }
    /// Receive encrypted data and decrypt it. The vec is reallocated. Might return an error.
    pub async fn receivedata(&mut self) -> io::Result<Vec<u8>> {
        let mut vec = Vec::new();
        vec.resize(MAXSIZE, 0);
        self.socket.readable().await?;
        let size = self.socket.read(&mut vec).await?;
        vec.resize(size, 0);
        let cipher = self.decryptdata(vec);
        if cipher.is_err() {
            return Err(io::Error::from(ErrorKind::InvalidData));
        }
        Ok(cipher.unwrap())
    }
    /// Encrypt data without sending to the socket. Might return an error.
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
    /// Decrypt data without sending to the socket. Might return an error.
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
