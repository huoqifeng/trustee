// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use super::*;
use async_trait::async_trait;
use base64::prelude::*;
use serde_json::json;
use crate::{InitDataHash, ReportData};
use crate::se::ibmse::FakeSeAttest;
use crate::se::ibmse::SeFakeVerifier;

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
        _tee_parameters: Option<Vec<u8>>,
    ) -> Result<String> {

        // TODO replace FakeSeAttest with real IBM SE crate
        let attester = FakeSeAttest::default();

        // TODO replace the placeholder
        let hkds: Vec<String> = vec![String::new(); 2];
        let certk = "cert_file_path";
        let signk = "sign_file_path";
        let arpk = "arpk_file_path";

        let extra_params = attester.create(hkds, certk, signk, arpk)
                            .await
                            .context("Create SE attestation request failed: {:?}")?;

        Ok(BASE64_STANDARD.encode(extra_params))
    }
}

async fn verify_evidence(
    evidence: &[u8],
    _expected_report_data: &ReportData<'_>,
    _expected_init_data_hash: &InitDataHash<'_>,
) -> Result<TeeEvidenceParsedClaim> {
    // TODO replace FakeSeAttest with real IBM SE crate
    let attester = FakeSeAttest::default();

    // TODO replace the placeholder
    let arpk = "arpk_file_path";
    let hdr = "hdr_file_path";

    let se = attester.verify(evidence, arpk, hdr)
                .await
                .context("Verify SE attestation evidence failed: {:?}")?;

    let claims_map = json!({
        "serial_number": format!("{}", "SE-ID"),
        "measurement": format!("{}", BASE64_STANDARD.encode(se.clone())),
        "report_data": format!("{}", BASE64_STANDARD.encode(se.clone())),
    });

    Ok(claims_map as TeeEvidenceParsedClaim)
}
