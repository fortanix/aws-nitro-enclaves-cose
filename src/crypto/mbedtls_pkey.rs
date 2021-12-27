//! MbedTLS PKey(Ref) implementation for cryptography
use mbedtls8::pk::EcGroupId;
use mbedtls8::pk::dsa::{serialize_signature, deserialize_signature};
use crate::{
    crypto::{HashFunction, SigningPrivateKey, SigningPublicKey},
    error::CoseError,
    sign::SignatureAlgorithm,
};

use mbedtls8::rng::Rdrand;
use mbedtls8::pk::Pk;

pub fn ec_curve_to_parameters(
    curve_name: EcGroupId,
) -> Result<(SignatureAlgorithm, HashFunction, usize), CoseError> {
    let sig_alg = match curve_name {
        // Recommended to use with SHA256
        EcGroupId::SecP256R1 => SignatureAlgorithm::ES256,
        // Recommended to use with SHA384
        EcGroupId::SecP384R1 => SignatureAlgorithm::ES384,
        // Recommended to use with SHA512
        EcGroupId::SecP521R1 => SignatureAlgorithm::ES512,
        _ => {
            return Err(CoseError::UnsupportedError(format!(
                "Curve name {:?} is not supported",
                curve_name
            )))
        }
    };

    Ok((
        sig_alg,
        sig_alg.suggested_hash_function(),
        sig_alg.key_length(),
    ))
}

impl SigningPublicKey for Pk
{
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, HashFunction), CoseError> {
        let curve_name = self.curve().map_err(|_| CoseError::UnsupportedError("Unsupported key".to_string()))?;
        let curve_parameters = ec_curve_to_parameters(curve_name)?;

        Ok((curve_parameters.0, curve_parameters.1))
    }

    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        let curve_name = self.curve().map_err(|_| CoseError::UnsupportedError("Unsupported key".to_string()))?;
        let (_, mdtype, key_length) = ec_curve_to_parameters(curve_name)?;

        // Recover the R and S factors from the signature contained in the object
        let (bytes_r, bytes_s) = signature.split_at(key_length);

        let sig = serialize_signature(bytes_r, bytes_s).map_err(CoseError::SignatureError)?;
        
        let md = mdtype.into();
        
        // We'll throw error if signature verify does not work
        match self.verify(md, &digest, &sig) {
            Ok(_) => Ok(true),
            Err(mbedtls8::Error::EcpVerifyFailed) => Ok(false),
            Err(e) => Err(CoseError::SignatureError(e)),
        }
    }
}

impl SigningPrivateKey for Pk
{
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CoseError> {
        let curve_name = self.curve().map_err(|_| CoseError::UnsupportedError("Unsupported key".to_string()))?;
        let (_, mdtype, key_length) = ec_curve_to_parameters(curve_name)?;
        
        let mut signature = vec![0u8; (self.len() + 7) / 8];

        let mut rng = Rdrand;

        let md = mdtype.into();

        let len = Pk::sign(self, md, digest, &mut signature, &mut rng).map_err(CoseError::EncryptionError)?;
        signature.truncate(len);        

        let (bytes_r, bytes_s) = deserialize_signature(&signature).map_err(CoseError::EncryptionError)?;
 
        // These should *never* exceed ceiling(key_length / 8)
        assert!(bytes_r.len() <= key_length);
        assert!(bytes_s.len() <= key_length);

        let mut signature_bytes = vec![0u8; key_length * 2];

        // This is big-endian encoding so padding might be added at the start if the factor is
        // too short.
        let offset_copy = key_length - bytes_r.len();
        signature_bytes[offset_copy..offset_copy + bytes_r.len()].copy_from_slice(&bytes_r);

        // This is big-endian encoding so padding might be added at the start if the factor is
        // too short.
        let offset_copy = key_length - bytes_s.len() + key_length;
        signature_bytes[offset_copy..offset_copy + bytes_s.len()].copy_from_slice(&bytes_s);

        Ok(signature_bytes)
    }
}
