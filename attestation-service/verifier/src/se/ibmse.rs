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

const EXIT_CODE_ATTESTATION_FAIL: u8 = 2;

#[derive(Serialize)]
struct VerifyOutput<'a> {
    cuid: HexSlice<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    additional_data: Option<HexSlice<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    additional_data_fields: Option<AdditionalData<HexSlice<'a>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_data: Option<HexSlice<'a>>,
}

impl<'a> VerifyOutput<'a> {
    fn from_exchange(ctx: &'a ExchangeFormatCtx, flags: &AttestationFlags) -> Result<Self> {
        let additional_data_fields = ctx
            .additional()
            .map(|a| AdditionalData::from_slice(a, flags))
            .transpose()?;
        let user_data = ctx.user().map(|u| u.into());

        Ok(Self {
            cuid: ctx.config_uid()?.into(),
            additional_data: ctx.additional().map(|a| a.into()),
            additional_data_fields,
            user_data,
        })
    }
}

impl<'a> Display for VerifyOutput<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Config UID:")?;
        writeln!(f, "{:#}", self.cuid)?;
        if let Some(data) = &self.additional_data {
            writeln!(f, "Additional-data:")?;
            writeln!(f, "{:#}", data)?;
        }
        if let Some(data) = &self.additional_data_fields {
            writeln!(f, "Additional-data content:")?;
            writeln!(f, "{:#}", data)?;
        }
        if let Some(data) = &self.user_data {
            writeln!(f, "user-data:")?;
            writeln!(f, "{:#}", data)?;
        }
        Ok(())
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
