use pqc_kyber::*;
use zeroize::Zeroize;
pub fn keypairfrom<R>(
    public: &mut [u8; KYBER_PUBLICKEYBYTES],
    secret: &mut [u8; KYBER_SECRETKEYBYTES],
    rng: &mut R,
) -> Result<Keypair, KyberError>
where
    R: RngCore + CryptoRng,
{
    //Try to encapsulate and decapsule to verify secret key matches public key
    let (ciphertext, shared_secret) = encapsulate(public, rng)?;
    let expected_shared_secret = decapsulate(&ciphertext, secret)?;
    //If it does match, return a KeyPair
    if expected_shared_secret == shared_secret {
        let mut public2 = *public;
        let mut secret2 = *secret;
        let key = Keypair {
            public: public2,
            secret: secret2,
        };
        public.zeroize();
        secret.zeroize();
        public2.zeroize();
        secret2.zeroize();
        Ok(key)
    } else {
        //Else return an error
        Err(KyberError::InvalidInput)
    }
}
