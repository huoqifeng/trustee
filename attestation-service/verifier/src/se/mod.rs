// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use async_trait::async_trait;
use anyhow::anyhow;
use base64::prelude::*;
use kbs_types::{Challenge, Tee};
use crate::{InitDataHash, ReportData};
use super::{TeeEvidenceParsedClaim, Verifier};
use crate::se::seattest::FakeSeAttest;
use crate::se::seattest::SeFakeVerifier;

pub mod seattest;

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
        verify_evidence(evidence, expected_report_data, expected_init_data_hash)
        .await
        .map_err(|e| anyhow!("Se Verifier: {:?}", e))
    }

    async fn generate_challenge(&self, tee: Tee, nonce: &str) -> Result<Challenge> {
        /// TODO replace FakeSeAttest with real crate
        let attester = FakeSeAttest::default();

        let hkds: Vec<String> = vec![String::new(); 2];
        let certk = String::new();
        let signk = String::new();
        let arpk = String::new();
        Result::Ok(Challenge {
            nonce,
            extra_params: BASE64_STANDARD.encode(attester.create(hkds, certk, signk, arpk)),
        })
    }
}

async fn verify_evidence(
    evidence: &[u8],
    expected_report_data: &ReportData<'_>,
    expected_init_data_hash: &InitDataHash<'_>,
) -> Result<TeeEvidenceParsedClaim> {
    /// TODO replace FakeSeAttest with real crate
    let attester = FakeSeAttest::default();

    let arpk = String::new();
    let hdr = String::new();
    let se = attester.verify(evidence, arpk, hdr);

    let v = serde_json::to_value(se?).context("build json value from the se evidence")?;
    Ok(v as TeeEvidenceParsedClaim)
}