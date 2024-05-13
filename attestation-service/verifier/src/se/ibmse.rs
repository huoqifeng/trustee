// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, warn};
use pv::{
    attest::{
        AdditionalData, AttestationFlags, AttestationItems, AttestationMeasAlg,
        AttestationMeasurement, AttestationRequest, AttestationVersion, ExchangeFormatCtx,
        ExchangeFormatVersion,
    },
    misc::{CertificateOptions, open_file, read_exact_file, write_file, HexSlice},
    request::{openssl::pkey::PKey, BootHdrTags, Confidential, ReqEncrCtx, Request, SymKey, SymKeyType},
};
use serde::Serialize;
use serde_yaml;
use std::{fmt::Display, io::Read, process::ExitCode};
use serde_with::base64::{Base64, Bcrypt, BinHex, Standard};

const EXIT_CODE_ATTESTATION_FAIL: u8 = 2;

//TODO implement getters or an into function to convert into pv::AttestationCmd(better approach)
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct S390xAttestationRequest {
    #[serde_as(as = "Base64")]
    request_blob: Vec<u8>,
    measurement_size: u32,
    additional_size: u32,
    //not the arpk but the real measuremtn key pv must provide a getter
    #[serde_as(as = "Base64")]
    encr_measurement_key: Vec<u8>,
    //not the arpk but the request nonce pv must provide a getter
    #[serde_as(as = "Base64")]
    encr_request_nonce: Vec<u8>,
    // IIRC the thing here should be stateless, therefore the request should contain the se header
    // as well, right? To save bytes, only the really required bytes are included here.
    //
    // For this to work I need to add the AsRef<[u8]> impl for that type to pv crate, but that is
    // very easy. as you see here:
    //
    // impl AsRef<[u8]> for BootHdrTags {
    //    fn as_ref(&self) -> &[u8] {
    //       self.as_bytes()
    //       }
    // }
    #[serde_as(as = "Base64")]
    image_hdr_tags: BootHdrTags,
}


impl S390xAttestationRequest {

// the caller of this fun then only has to serielize the request in (using serde-json) e.g. json and send it via the
    // network 


pub fn create(hkds: Vec<String>, certs: Vec<String>, crls: Vec<String>, image_hdr_tags: BootHdrTags) -> Result<Self> {
    let att_version = AttestationVersion::One;
    let meas_alg = AttestationMeasAlg::HmacSha512;

    let mut att_flags = AttestationFlags::default();
    let mut arcb = AttestationRequest::new(att_version, meas_alg, att_flags)?;

    let verifier = CertVerifier::new(certs.as_slice(), crls.as_slice(), None, false)?;
        
    let mut arcb = AttestationRequest::new(att_version, meas_alg, att_flags)?;
        for hkd in hkds {
            let hk = read_file(hkd, "host-key document")?;
            let certs = read_certs(&hk).map_err(|source| Error::HkdNotPemOrDer {
                hkd: hkd.to_string(),
                source,
            })?;
            if certs.is_empty() {
                todo!();
            }
            if certs.len() != 1 {
                todo!();
            }

            // Panic: len is == 1 -> unwrap will succeed/not panic
            let c = certs.first().unwrap();
            verifier.verify(c)?;
            arcb.add_hostkey(c.public_key()?);
        }
        let encr_ctx =
        ReqEncrCtx::random(SymKeyType::Aes256)?;
        let request_blob = arcb.encrypt(&encr_ctx)?;

        let encr_measurement_key = /* TODO encrypt data I need to provide a getter for this in the pv crate*/;
        let encr_request_nonce = /* TODO encrypt data I need to provide a getter for this in the pv crate*/;

Self{
request_blob,
            measurement_size: meas_alg.expected_size(),
additional_size: arcb.flags().expected_additional_size(),
encr_measurement_key,
encr_request_nonce,
image_hdr_tags
        }

    }
}
/// the caller of this fn has to deserialize the request first and serialize the result


//TODO insert user data
fn poc_calc_measurement(req: &S390xAttestationRequest) -> Result<S390xAttestationResponse> {

    let mut uvc: AttestationCmd = req.into(); //TODO impl Into<AttestatioCmd> in this crate
    let uv = Uvdevice::open()?;
    uv.send_cmd(&mut uvc)?;

    let res = uvc.into(); //TODO impl Into<S390xAttestationResponse> in this crate
Ok(res)

}



//TODO implement getters or an into function to convert from pv::AttestationCmd(better approach)
//and into 
#[derive(Debug, Serialize, Deserialize)]
pub struct S390xAttestationResponse {
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

impl S390xAttestationResponse {
fn verify(&self) -> Result<Todo> {
    let meas_key = ...;
        let nonce = ...;


    let meas_key = PKey::hmac(conf.meas_key())?;
let items = AttestationItems::new(self.image_hdr_tags, ....)?


    let measurement =
        AttestationMeasurement::calculate(items, AttestationMeasAlg::HmacSha512, &meas_key)?;

//todo check measuremt
        // do something with additonal data, user_data, ....

    }

    

}






pub fn verify(input: &mut dyn Read, hdr_file: String, arpk_file: String, output: &mut Vec<u8>, user_data: &mut Vec<u8>) -> Result<ExitCode> {
    let mut img = open_file(&hdr_file)?;
    let arpk = SymKey::Aes256(
        read_exact_file(&arpk_file, "Attestation request protection key").map(Confidential::new)?,
    );
    let hdr = BootHdrTags::from_se_image(&mut img)?;
    let ctx = ExchangeFormatCtx::read(mut input, true)?;

    let (auth, conf) = AttestationRequest::decrypt_bin(ctx.arcb(), &arpk)?;
    let meas_key = PKey::hmac(conf.measurement_key())?;
    let items = AttestationItems::from_exchange(&ctx, &hdr, conf.nonce())?;

    let measurement =
        AttestationMeasurement::calculate(items, AttestationMeasAlg::HmacSha512, &meas_key)?;

    let uv_meas = ctx.measurement().ok_or(anyhow!(
        "The input is missing the measurement. It is probably no attestation response"
    ))?;
    if !measurement.eq_secure(uv_meas) {
        debug!("Measurement values:");
        debug!("Recieved: {}", HexSlice::from(uv_meas));
        debug!("Calculated: {}", HexSlice::from(measurement.as_ref()));
        warn!("Attestation measurement verification failed. Calculated and received attestation measurement are not equal.");
        return Ok(ExitCode::from(EXIT_CODE_ATTESTATION_FAIL));
    }
    warn!("Attestation measurement verified");
    // Error impossible CUID is present Attestation verified
    let pr_data = VerifyOutput::from_exchange(&ctx, auth.flags())?;

    warn!("{pr_data}");
    serde_yaml::to_writer(output, &pr_data)?;

    // How to get user_data, what's data here???
    if let Some(user_data) = &user_data {
        match ctx.user() {
            Some(data) => write_file(user_data, data, "user-data")?,
            None => {
                warn!("Location for `user-data` specified, but respose does not contain any user-data")
            }
        }
    };

    Ok(ExitCode::SUCCESS)
}

pub fn create(host_key_documents: Vec<String>, certs: Vec<String>, crls: Vec<String>, arpk_file: String, root_ca: Option<String>) -> Result<Vec<u8>> {
    let att_version = AttestationVersion::One;
    let meas_alg = AttestationMeasAlg::HmacSha512;

    let mut att_flags = AttestationFlags::default();
    att_flags.set_image_phkh();

    let mut arcb = AttestationRequest::new(att_version, meas_alg, att_flags)?;
    debug!("Generated Attestation request");

    let certificate_args = CertificateOptions {
        host_key_documents,
        no_verify: true,
        certs,
        crls, 
        offline: true,
        root_ca,
    };
    // Add host-key documents
    certificate_args
        .get_verified_hkds("attestation request")?
        .into_iter()
        .for_each(|k| arcb.add_hostkey(k));
    debug!("Added all host-keys");

    let encr_ctx =
        ReqEncrCtx::random(SymKeyType::Aes256).context("Failed to generate random input")?;
    let ser_arcb = arcb.encrypt(&encr_ctx)?;
    warn!("Successfully generated the request");

    let output: Vec<u8>;
    let exch_ctx = ExchangeFormatCtx::new_request(
        ser_arcb,
        meas_alg.exp_size(),
        arcb.flags().expected_additional_size().into(),
    )?;
    exch_ctx.write(&mut output, ExchangeFormatVersion::One)?;

    let arpk = match encr_ctx.prot_key() {
        SymKey::Aes256(k) => k,
        _ => bail!("Unexpected key type"),
    };
    write_file(
        &arpk_file,
        arpk.value(),
        "Attestation request Protection Key",
    )?;

    Result::Ok(output)
}
