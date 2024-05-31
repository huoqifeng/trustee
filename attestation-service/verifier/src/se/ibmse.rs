// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate lazy_static;
use anyhow::{anyhow, bail, Result};
use log::{debug, info, warn};
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
use std::{fs::File, io::Read, sync::Mutex};

lazy_static::lazy_static! {
    static ref PUB_KEY_FILE_CONTENTS: Mutex<Option<Vec<u8>>> = Mutex::new(None);
    static ref PRI_KEY_FILE_CONTENTS: Mutex<Option<Vec<u8>>> = Mutex::new(None);
}

fn get_cached_file_or_read(filename: &str, content_ref: &Mutex<Option<Vec<u8>>>) -> Result<Vec<u8>> {
    let mut guard = content_ref.lock().map_err(|_| anyhow!("Failed to acquire lock"))?;

    if let Some(contents) = guard.as_ref().cloned() {
        info!("Reading key_file contents from cache.");
        Ok(contents)
    } else {
        info!("Reading key_file contents from file.");
        let mut file = File::open(filename)?;
        let mut contents = vec![];
        file.read_to_end(&mut contents)?;
        *guard = Some(contents.clone());
        Ok(contents)
    }
}

fn encrypt_measurement_key(key: &[u8], rsa_public_key: &PKey<Public>) -> Result<Vec<u8>> {
    info!("encrypt_measurement_key.");
    let mut encrypter = Encrypter::new(rsa_public_key)?;
    encrypter.set_rsa_padding(Padding::PKCS1)?;

    let buffer_len = encrypter.encrypt_len(key)?;
    let mut encrypted_hmac_key = vec![0; buffer_len];
    let len = encrypter.encrypt(key, &mut encrypted_hmac_key)?;
    encrypted_hmac_key.truncate(len);

    Ok(encrypted_hmac_key)
}

fn decrypt_measurement_key(key: &[u8], rsa_private_key: &PKey<Private>) -> Result<Vec<u8>> {
    info!("decrypt_measurement_key.");
    let mut decrypter = Decrypter::new(rsa_private_key)?;
    decrypter.set_rsa_padding(Padding::PKCS1)?;

    let buffer_len = decrypter.decrypt_len(key)?;
    let mut decrypted_hmac_key = vec![0; buffer_len];
    let decrypted_len = decrypter.decrypt(key, &mut decrypted_hmac_key)?;
    decrypted_hmac_key.truncate(decrypted_len);

    Ok(decrypted_hmac_key)
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserData {
    #[serde_as(as = "Base64")]
    image_btph: Vec<u8>,
}

#[repr(C)]
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
            let c = certs
                .first()
                .ok_or(anyhow!("File does not contain a X509 certificate"))?;
            verifier.verify(c)?;
            arcb.add_hostkey(c.public_key()?);
        }
        let encr_ctx = ReqEncrCtx::random(SymKeyType::Aes256)?;
        let request_blob = arcb.encrypt(&encr_ctx)?;
        let contents = get_cached_file_or_read(pub_key_file, &PUB_KEY_FILE_CONTENTS)?;
        let rsa = Rsa::public_key_from_pem(&contents)?;
        let rsa_public_key = &PKey::from_rsa(rsa)?;

        let conf_data = arcb.confidential_data();
        let encr_measurement_key =
            encrypt_measurement_key(conf_data.measurement_key(), rsa_public_key)?;
        let binding = conf_data
            .nonce()
            .clone()
            .ok_or(anyhow!("Failed to get nonce binding"))?;
        let nonce = binding.value();
        let encr_request_nonce = encrypt_measurement_key(nonce, rsa_public_key)?;

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
    pub fn verify(&self, priv_key_file: &str) -> Result<SeAttestationClaims> {
        let contents = get_cached_file_or_read(priv_key_file, &PRI_KEY_FILE_CONTENTS)?;

        let rsa = Rsa::private_key_from_pem(&contents)?;
        let rsa_private_key = &PKey::from_rsa(rsa)?;

        let meas_key = decrypt_measurement_key(&self.encr_measurement_key, rsa_private_key)?;
        let nonce = decrypt_measurement_key(&self.encr_request_nonce, rsa_private_key)?;

        if nonce.len() != 16 {
            bail!("The nonce vector must have exactly 16 elements.");
        }

        let nonce_array: [u8; 16] = nonce
            .try_into()
            .map_err(|_| anyhow!("Failed to convert nonce from Vec<u8> to [u8; 16]."))?;
        let meas_key = &PKey::hmac(&meas_key)?;
        let items = AttestationItems::new(
            &self.image_hdr_tags,
            &self.cuid,
            Some(&self.user_data),
            Some(&nonce_array),
            Some(&self.additional_data),
        );

        let measurement =
            AttestationMeasurement::calculate(items, AttestationMeasAlg::HmacSha512, meas_key)?;

        if !measurement.eq_secure(&self.measurement) {
            debug!("Recieved: {:?}", self.measurement);
            debug!("Calculated: {:?}", measurement.as_ref());
            warn!("Attestation measurement verification failed. Calculated and received attestation measurement are not equal.");
            bail!("Failed to verify the measurement!");
        }
        
        // TODO check self.user_data.image_btph with previous saved value

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
    info!("IBM SE create API called.");
    debug!("hkds: {:#?}", hkds);
    debug!("certs: {:#?}", certs);
    debug!("ca: {:#?}", ca);
    debug!("se_img_hdr: {:#?}", se_img_hdr);
    debug!("pub_key_file: {:#?}", pub_key_file);

    let mut hdr_file = open_file(se_img_hdr)?;
    let mut image_hdr_tags = BootHdrTags::from_se_image(&mut hdr_file)?;
    let root_ca = Some(ca);

    let se_request = SeAttestationRequest::create(
        hkds,
        certs,
        crls,
        root_ca,
        &mut image_hdr_tags,
        pub_key_file,
    )?;

    let challenge = serde_json::to_string(&se_request)?;
    debug!("challenge json: {:#?}", challenge);

    Ok(challenge)
}

pub fn verify(response: &[u8], priv_key_file: &str) -> Result<SeAttestationClaims> {
    info!("IBM SE verify API called.");
    // response is serialized SeAttestationResponse String bytes
    let response_str = std::str::from_utf8(response)?;
    debug!("SeAttestationResponse json: {:#?}", response_str);
    let se_response: SeAttestationResponse = serde_json::from_str(response_str)?;

    let claims = se_response.verify(priv_key_file)?;
    debug!("claims json: {:#?}", claims);

    Ok(claims)
}
