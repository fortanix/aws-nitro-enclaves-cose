use crate::{crypto::HashFunction, encrypt::COSEAlgorithm};
use mbedtls8::hash::{Md, Type as MdType};
use mbedtls8::cipher::{Authenticated, Cipher, Decryption, Encryption};
use mbedtls8::cipher::raw::{CipherId, CipherMode};
use mbedtls8::rng::{Rdrand, Random};

/// The type of errors reported
pub type CryptoError = mbedtls8::Error;

/// Compute a message digest (hash), given a hash function and data
pub fn hash(hf: HashFunction, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let md = MdType::from(hf);

    let mut output = vec![0u8; 64]; // biggest in SHA-512
    let len = Md::hash(md, data, &mut output)?;
    output.truncate(len);
    Ok(output)
}

impl From<HashFunction> for MdType {
    fn from(hf: HashFunction) -> MdType {
        match hf {
            HashFunction::Sha256 => MdType::Sha256,
            HashFunction::Sha384 => MdType::Sha384,
            HashFunction::Sha512 => MdType::Sha512,
        }
    }
}

impl COSEAlgorithm {
    pub(crate) fn encrypt(
        &self,
        key: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), CryptoError> {

        let (cipher_id, key_length, cipher_mode, iv_length) = match *self {
            COSEAlgorithm::AesGcm96_128_128 => (CipherId::Aes, 128, CipherMode::GCM, 12),
            COSEAlgorithm::AesGcm96_128_192 => (CipherId::Aes, 192, CipherMode::GCM, 12),
            COSEAlgorithm::AesGcm96_128_256 => (CipherId::Aes, 256, CipherMode::GCM, 12),
        };
        
        let cipher = Cipher::<Encryption, Authenticated, _>::new(cipher_id, cipher_mode, 8 * key_length as u32)?;

        let mut iv  = vec![0; iv_length];
        let mut rng = Rdrand;
        rng.random(&mut iv)?;

        let cipher = cipher.set_key_iv(&key, &iv)?;
        
        let out_len = plaintext.len() + self.tag_size();
        let mut cipher_and_tag = vec![0; out_len];

        cipher.encrypt_auth(aad, plaintext, &mut cipher_and_tag, self.tag_size())?;

        Ok((cipher_and_tag, Some(iv)))
    }

    pub(crate) fn decrypt(
        &self,
        key: &[u8],
        aad: &[u8],
        iv: Option<&[u8]>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        
        let (cipher_id, key_length, cipher_mode, iv_length) = match *self {
            COSEAlgorithm::AesGcm96_128_128 => (CipherId::Aes, 128, CipherMode::GCM, 16),
            COSEAlgorithm::AesGcm96_128_192 => (CipherId::Aes, 192, CipherMode::GCM, 16),
            COSEAlgorithm::AesGcm96_128_256 => (CipherId::Aes, 256, CipherMode::GCM, 16),
        };

        let iv = iv.ok_or(mbedtls8::Error::CipherBadInputData)?;

        if iv.len() != iv_length {
            return Err(mbedtls8::Error::CipherBadInputData);
        }
        
        let cipher = Cipher::<Decryption, Authenticated, _>::new(cipher_id, cipher_mode, 8 * key_length as u32)?;
        let cipher = cipher.set_key_iv(&key, &iv)?;

        let mut plain = vec![0u8; ciphertext.len()];
        cipher.decrypt_auth(aad, &ciphertext, &mut plain, self.tag_size())?;

        Ok(plain)
    }
}
