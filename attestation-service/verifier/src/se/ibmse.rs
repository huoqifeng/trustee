// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Result};
use log::{debug, warn};
use openssl::{
    encrypt::{Decrypter, Encrypter},
    pkey::{PKey, Private, Public},
    rsa::{Padding, Rsa},
};
use pv::{
    attest::{
        AdditionalData, AttestationFlags, AttestationItems, AttestationMeasAlg,
        AttestationMeasurement, AttestationRequest, AttestationVersion,
    },
    misc::{open_file, read_certs, read_file},
    request::{BootHdrTags, CertVerifier, HkdVerifier, ReqEncrCtx, Request, SymKeyType},
    uv::ConfigUid,
};
use serde::{Deserialize, Serialize};
use serde_json;
use serde_with::{base64::Base64, serde_as};
use std::{fs::File, io::Read};

fn encrypt_measurement_key(key: &[u8], rsa_public_key: &PKey<Public>) -> Vec<u8> {
    let mut encrypter = Encrypter::new(rsa_public_key).unwrap();
    encrypter.set_rsa_padding(Padding::PKCS1).unwrap();

    let buffer_len = encrypter.encrypt_len(key).unwrap();
    let mut encrypted_hmac_key = vec![0; buffer_len];
    let len = encrypter.encrypt(key, &mut encrypted_hmac_key).unwrap();
    encrypted_hmac_key.truncate(len);

    encrypted_hmac_key
}

fn decrypt_measurement_key(key: &[u8], rsa_private_key: &PKey<Private>) -> Vec<u8> {
    let mut decrypter = Decrypter::new(rsa_private_key).unwrap();
    decrypter.set_rsa_padding(Padding::PKCS1).unwrap();

    let buffer_len = decrypter.decrypt_len(key).unwrap();
    let mut decrypted_hmac_key = vec![0; buffer_len];
    let decrypted_len = decrypter.decrypt(key, &mut decrypted_hmac_key).unwrap();
    decrypted_hmac_key.truncate(decrypted_len);

    decrypted_hmac_key
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserData {
    #[serde_as(as = "Base64")]
    image_btph: Vec<u8>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct SeAttestationClaims {
    #[serde_as(as = "Base64")]
    cuid: ConfigUid,
    #[serde_as(as = "Base64")]
    user_data: Vec<u8>,
    version: u32,
    #[serde_as(as = "Base64")]
    image_phkh: Vec<u8>,
    #[serde_as(as = "Base64")]
    attestation_phkh: Vec<u8>,
    #[serde_as(as = "Base64")]
    tag: [u8; 16],
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct SeAttestationRequest {
    #[serde_as(as = "Base64")]
    request_blob: Vec<u8>,
    measurement_size: u32,
    additional_size: u32,
    #[serde_as(as = "Base64")]
    encr_measurement_key: Vec<u8>,
    #[serde_as(as = "Base64")]
    encr_request_nonce: Vec<u8>,
    #[serde_as(as = "Base64")]
    image_hdr_tags: BootHdrTags,
}

impl SeAttestationRequest {
    pub fn from_slice(request: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(request).unwrap())
    }

    pub fn from_string(request: &str) -> Result<Self> {
        Ok(serde_json::from_str(request).unwrap())
    }

    pub fn create(
        hkds: &Vec<String>,
        certs: &Vec<String>,
        crls: &Vec<String>,
        root_ca_path: Option<String>,
        image_hdr_tags: &mut BootHdrTags,
        pub_key_file: &str,
    ) -> Result<Self> {
        let att_version = AttestationVersion::One;
        let meas_alg = AttestationMeasAlg::HmacSha512;

        let mut att_flags = AttestationFlags::default();
        att_flags.set_image_phkh();
        att_flags.set_attest_phkh();
        let mut arcb = AttestationRequest::new(att_version, meas_alg, att_flags)?;
        let verifier = CertVerifier::new(certs.as_slice(), crls.as_slice(), root_ca_path, false)?;

        for hkd in hkds {
            let hk = read_file(hkd, "host-key document")?;
            let certs = read_certs(&hk)?;
            if certs.is_empty() {
                warn!("The host key document in '{hkd}' contains empty certificate!");
            }
            if certs.len() != 1 {
                warn!("The host key document in '{hkd}' contains more than one certificate!")
            }
            // Panic: len is == 1 -> unwrap will succeed/not panic
            let c = certs.first().unwrap();
            verifier.verify(c)?;
            arcb.add_hostkey(c.public_key()?);
        }
        let encr_ctx = ReqEncrCtx::random(SymKeyType::Aes256)?;
        let request_blob = arcb.encrypt(&encr_ctx)?;
        
        let mut file = File::open(pub_key_file)?;
        let mut contents = vec![];
        file.read_to_end(&mut contents)?;
        let rsa = Rsa::public_key_from_pem(&contents)?;
        let rsa_public_key = &PKey::from_rsa(rsa)?;

        let conf_data = arcb.confidential_data();
        let encr_measurement_key =
            encrypt_measurement_key(conf_data.measurement_key(), rsa_public_key);
        let encr_request_nonce =
            encrypt_measurement_key(conf_data.nonce().clone().unwrap().value(), rsa_public_key);

        Ok(Self {
            request_blob,
            measurement_size: meas_alg.exp_size(),
            additional_size: arcb.flags().expected_additional_size(),
            encr_measurement_key,
            encr_request_nonce,
            image_hdr_tags: *image_hdr_tags,
        })
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct SeAttestationResponse {
    #[serde_as(as = "Base64")]
    measurement: Vec<u8>,
    #[serde_as(as = "Base64")]
    additional_data: Vec<u8>,
    #[serde_as(as = "Base64")]
    user_data: Vec<u8>,
    #[serde_as(as = "Base64")]
    cuid: ConfigUid,
    #[serde_as(as = "Base64")]
    encr_measurement_key: Vec<u8>,
    #[serde_as(as = "Base64")]
    encr_request_nonce: Vec<u8>,
    #[serde_as(as = "Base64")]
    image_hdr_tags: BootHdrTags,
}

impl SeAttestationResponse {
    pub fn from_slice(response: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(response).unwrap())
    }

    pub fn from_string(request: &str) -> Result<Self> {
        Ok(serde_json::from_str(request).unwrap())
    }

    pub fn create(
        measurement: &[u8],
        additional_data: &[u8],
        user_data: &[u8],
        cuid: &ConfigUid,
        encr_measurement_key: &[u8],
        encr_request_nonce: &[u8],
        image_hdr_tags: &BootHdrTags,
    ) -> Result<Self> {
        Ok(Self {
            measurement: measurement.to_vec(),
            additional_data: additional_data.to_vec(),
            user_data: user_data.to_vec(),
            cuid: *cuid,
            encr_measurement_key: encr_measurement_key.to_vec(),
            encr_request_nonce: encr_request_nonce.to_vec(),
            image_hdr_tags: *image_hdr_tags,
        })
    }

    pub fn verify(&self, priv_key_file: &str) -> Result<SeAttestationClaims> {
        let mut file = File::open(priv_key_file)?;
        let mut contents = vec![];
        file.read_to_end(&mut contents)?;

        let rsa = Rsa::private_key_from_pem(&contents)?;
        let rsa_private_key = &PKey::from_rsa(rsa)?;

        let meas_key = decrypt_measurement_key(&self.encr_measurement_key, rsa_private_key);
        let nonce = decrypt_measurement_key(&self.encr_request_nonce, rsa_private_key);

        if nonce.len() != 16 {
            return Err(anyhow!("The nonce vector must have exactly 16 elements."));
        }
        let boxed_slice: Box<[u8]> = nonce.into_boxed_slice();
        let boxed_array: Box<[u8; 16]> = match boxed_slice.try_into() {
            Ok(ba) => ba,
            Err(_) => return Err(anyhow!("Failed to convert nonce from Vec<u8> to [u8; 16].")),
        };
        let nonce_array: [u8; 16] = *boxed_array;

        let meas_key = &PKey::hmac(&meas_key)?;
        let items = AttestationItems::new(
            &self.image_hdr_tags,
            &self.cuid,
            Some(&self.user_data),
            Some(&nonce_array),
            Some(&self.additional_data),
        );

        let measurement =
            AttestationMeasurement::calculate(items, AttestationMeasAlg::HmacSha512, meas_key)
                .unwrap();

        if !measurement.eq_secure(&self.measurement) {
            debug!("Recieved: {:?}", self.measurement);
            debug!("Calculated: {:?}", measurement.as_ref());
            warn!("Attestation measurement verification failed. Calculated and received attestation measurement are not equal.");
            return Err(anyhow!("Failed to verify the measurement!"));
        }
        
        // let userdata = serde_json::from_slice(&self.user_data)?;
        // debug!("user_data: {:?}", userdata);
        // TODO check UserData.image_btph with previous saved value

        let mut att_flags = AttestationFlags::default();
        att_flags.set_image_phkh();
        att_flags.set_attest_phkh();
        let add_data = AdditionalData::from_slice(&self.additional_data, &att_flags)?;
        debug!("additional_data: {:?}", add_data);
        let image_phkh = add_data
            .image_public_host_key_hash()
            .ok_or(anyhow!("Failed to get image_public_host_key_hash."))?;
        let attestation_phkh = add_data
            .attestation_public_host_key_hash()
            .ok_or(anyhow!("Failed to get attestation_public_host_key_hash."))?;

        // TODO image_phkh and attestation_phkh with previous saved value

        let claims = SeAttestationClaims {
            cuid: self.cuid,
            user_data: self.user_data.clone(),
            version: AttestationVersion::One as u32,
            image_phkh: image_phkh.to_vec(),
            attestation_phkh: attestation_phkh.to_vec(),
            tag: *self.image_hdr_tags.tag(),
        };
        Ok(claims)
    }
}

pub fn create(
    hkds: &Vec<String>,
    certs: &Vec<String>,
    crls: &Vec<String>,
    ca: String,
    se_img_hdr: &str,
    pub_key_file: &str,
) -> Result<String> {
    debug!("hkds: {:#?}", hkds);
    debug!("certs: {:#?}", certs);
    debug!("ca: {:#?}", ca);
    debug!("se_img_hdr: {:#?}", se_img_hdr);
    debug!("pub_key_file: {:#?}", pub_key_file);

    let mut hdr_file = open_file(se_img_hdr)?;
    let mut image_hdr_tags = BootHdrTags::from_se_image(&mut hdr_file).unwrap();
    let root_ca = Some(ca);

    let se_request = SeAttestationRequest::create(
        hkds,
        certs,
        crls,
        root_ca,
        &mut image_hdr_tags,
        pub_key_file,
    )
    .unwrap();

    let challenge = serde_json::to_string(&se_request)?;
    debug!("challenge json: {:#?}", challenge);

    Ok(challenge)
}

pub fn verify(response: &[u8], priv_key_file: &str) -> Result<SeAttestationClaims> {
    // response is serialized SeAttestationResponse String bytes
    let response_str = std::str::from_utf8(response)?;
    debug!("SeAttestationResponse json: {:#?}", response_str);
    let se_response = SeAttestationResponse::from_string(response_str)?;

    let claims = se_response.verify(priv_key_file)?;
    debug!("claims json: {:#?}", claims);

    Ok(claims)
}
