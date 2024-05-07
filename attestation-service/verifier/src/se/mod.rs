// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use super::*;
use async_trait::async_trait;
use base64::prelude::*;
use serde_json::json;
use std::io::Cursor;
use pv::misc::CertificateOptions;
use crate::{InitDataHash, ReportData};

pub mod ibmse;

#[derive(Debug, Default)]
pub struct SeVerifier {}

#[async_trait]
impl Verifier for SeVerifier {
    async fn evaluate(
        &self,
        evidence: &[u8],
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<TeeEvidenceParsedClaim> {
        verify_evidence(evidence, expected_report_data, expected_init_data_hash).await
    }

    async fn generate_supplemental_challenge(
        &self,
        _tee_parameters: String,
    ) -> Result<String> {
        let hkds: Vec<String> = vec![String::new(); 2];
        let certs: Vec<String> = vec![String::new(); 2];
        let crls: Vec<String> = vec![];
        let arpk = String::from("arpk_file_path");
        let root_ca = Option::Some(String::from("root_ca"));

        let challenge = ibmse::create(hkds, certs, crls, arpk, root_ca)?;

        Ok(BASE64_STANDARD.encode(challenge))
    }
}

async fn verify_evidence(
    evidence: &[u8],
    _expected_report_data: &ReportData<'_>,
    _expected_init_data_hash: &InitDataHash<'_>,
) -> Result<TeeEvidenceParsedClaim> {
    let arpk = String::from("arpk_file_path");
    let hdr = String::from("hdr_file_path");

    let mut cursor = Cursor::new(evidence);
    let mut output: Vec<u8> = vec![];
    let mut userdata: Vec<u8> = vec![];
    let _res = ibmse::verify(&mut cursor, hdr, arpk, &mut output, &mut userdata);

    let claims_map = json!({
        "serial_number": format!("{}", "SE-ID"),
        "measurement": format!("{}", BASE64_STANDARD.encode(output.clone())),
        "report_data": format!("{}", BASE64_STANDARD.encode(userdata.clone())),
    });

    Ok(claims_map as TeeEvidenceParsedClaim)
}
