// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use super::*;
use crate::se::ibmse::SeAttestationClaims;
use crate::{InitDataHash, ReportData};
use async_trait::async_trait;
use std::fs;

pub mod ibmse;

const SE_HOST_KEY_DOCUMENTS_ROOT: &str = "/run/confidential-containers/ibmse/hkds";
const SE_CERTIFICATES_ROOT: &str = "/run/confidential-containers/ibmse/certs";
const SE_CERTIFICATE_ROOT_CA: &str = "/run/confidential-containers/ibmse/certs/ca";
const SE_CERTIFICATE_REVOCATION_LISTS_ROOT: &str = "/run/confidential-containers/ibmse/crls";
const SE_IMAGE_HEADER_FILE: &str = "/run/confidential-containers/ibmse/hdr/hdr.bin";
const SE_MEASUREMENT_ENCR_KEY_PRIVATE: &str =
    "/run/confidential-containers/ibmse/rsa/encrypt_key.pem";
const SE_MEASUREMENT_ENCR_KEY_PUBLIC: &str =
    "/run/confidential-containers/ibmse/rsa/encrypt_key.pub";

fn list_files_in_folder(dir: &str) -> Result<Vec<String>> {
    let mut file_paths = Vec::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            if let Some(path_str) = path.to_str() {
                file_paths.push(path_str.to_string());
            }
        }
    }

    Ok(file_paths)
}

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
        let hkds = list_files_in_folder(SE_HOST_KEY_DOCUMENTS_ROOT)?;
        let certs = list_files_in_folder(SE_CERTIFICATES_ROOT)?;
        let crls = list_files_in_folder(SE_CERTIFICATE_REVOCATION_LISTS_ROOT)?;
        let ca = String::from(SE_CERTIFICATE_ROOT_CA);
        // challenge is Serialized SeAttestationRequest, attester uses it to do perform action
        // attester then generates and return Serialized SeAttestationResponse
        ibmse::create(
            &hkds,
            &certs,
            &crls,
            ca,
            SE_IMAGE_HEADER_FILE,
            SE_MEASUREMENT_ENCR_KEY_PUBLIC,
        )
    }
}

async fn verify_evidence(
    evidence: &[u8],
    _expected_report_data: &ReportData<'_>,
    _expected_init_data_hash: &InitDataHash<'_>,
) -> Result<TeeEvidenceParsedClaim> {
    // evidence is serialized SeAttestationResponse String bytes
    let mut se_claims = ibmse::verify(evidence, SE_MEASUREMENT_ENCR_KEY_PRIVATE)?;
    se_generate_parsed_claim(&mut se_claims).map_err(|e| anyhow!("error from se Verifier: {:?}", e))
}

fn se_generate_parsed_claim(se_claims: &mut SeAttestationClaims) -> Result<TeeEvidenceParsedClaim> {
    let v = serde_json::to_value(se_claims).context("build json value from the se claims")?;
    Ok(v as TeeEvidenceParsedClaim)
}
