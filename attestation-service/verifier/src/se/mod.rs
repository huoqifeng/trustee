// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use super::*;
use crate::se::ibmse::SeAttestationClaims;
use crate::{InitDataHash, ReportData};
use async_trait::async_trait;
use core::result::Result::Ok;
use std::{env, fs};

pub mod ibmse;

const DEFAULT_SE_HOST_KEY_DOCUMENTS_ROOT: &str = "/run/confidential-containers/ibmse/hkds";
const DEFAULT_SE_CERTIFICATES_ROOT: &str = "/run/confidential-containers/ibmse/certs";
const DEFAULT_SE_CERTIFICATE_ROOT_CA: &str = "/run/confidential-containers/ibmse/certs/ca";
const DEFAULT_SE_CERTIFICATE_REVOCATION_LISTS_ROOT: &str = "/run/confidential-containers/ibmse/crls";
const DEFAULT_SE_IMAGE_HEADER_FILE: &str = "/run/confidential-containers/ibmse/hdr/hdr.bin";
const DEFAULT_SE_MEASUREMENT_ENCR_KEY_PRIVATE: &str =
    "/run/confidential-containers/ibmse/rsa/encrypt_key.pem";
const DEFAULT_SE_MEASUREMENT_ENCR_KEY_PUBLIC: &str =
    "/run/confidential-containers/ibmse/rsa/encrypt_key.pub";

fn get_hkds_root() -> String {
    if let Ok(env_path) = env::var("SE_HOST_KEY_DOCUMENTS_ROOT") {
        return env_path;
    }
    DEFAULT_SE_HOST_KEY_DOCUMENTS_ROOT.into()
}

fn get_certs_root() -> String {
    if let Ok(env_path) = env::var("SE_CERTIFICATES_ROOT") {
        return env_path;
    }
    DEFAULT_SE_CERTIFICATES_ROOT.into()
}

fn get_root_ca_file() -> String {
    if let Ok(env_path) = env::var("SE_CERTIFICATE_ROOT_CA") {
        return env_path;
    }
    DEFAULT_SE_CERTIFICATE_ROOT_CA.into()
}

fn get_crls_root() -> String {
    if let Ok(env_path) = env::var("SE_CERTIFICATE_REVOCATION_LISTS_ROOT") {
        return env_path;
    }
    DEFAULT_SE_CERTIFICATE_REVOCATION_LISTS_ROOT.into()
}

fn get_img_hdr_file() -> String {
    if let Ok(env_path) = env::var("SE_IMAGE_HEADER_FILE") {
        return env_path;
    }
    DEFAULT_SE_IMAGE_HEADER_FILE.into()
}

fn get_encrypt_priv_keyfile() -> String {
    if let Ok(env_path) = env::var("SE_MEASUREMENT_ENCR_KEY_PRIVATE") {
        return env_path;
    }
    DEFAULT_SE_MEASUREMENT_ENCR_KEY_PRIVATE.into()
}

fn get_encrypt_pub_keyfile() -> String {
    if let Ok(env_path) = env::var("SE_MEASUREMENT_ENCR_KEY_PUBLIC") {
        return env_path;
    }
    DEFAULT_SE_MEASUREMENT_ENCR_KEY_PUBLIC.into()
}

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
        let hkds = list_files_in_folder(&get_hkds_root())?;
        let certs = list_files_in_folder(&get_certs_root())?;
        let crls = list_files_in_folder(&get_crls_root())?;
        // challenge is Serialized SeAttestationRequest, attester uses it to do perform action
        // attester then generates and return Serialized SeAttestationResponse
        ibmse::create(
            &hkds,
            &certs,
            &crls,
            get_root_ca_file(),
            &get_img_hdr_file(),
            &get_encrypt_pub_keyfile(),
        )
    }
}

async fn verify_evidence(
    evidence: &[u8],
    _expected_report_data: &ReportData<'_>,
    _expected_init_data_hash: &InitDataHash<'_>,
) -> Result<TeeEvidenceParsedClaim> {
    // evidence is serialized SeAttestationResponse String bytes
    let mut se_claims = ibmse::verify(evidence, &get_encrypt_priv_keyfile())?;
    se_generate_parsed_claim(&mut se_claims).map_err(|e| anyhow!("error from se Verifier: {:?}", e))
}

fn se_generate_parsed_claim(se_claims: &mut SeAttestationClaims) -> Result<TeeEvidenceParsedClaim> {
    let v = serde_json::to_value(se_claims).context("build json value from the se claims")?;
    Ok(v as TeeEvidenceParsedClaim)
}
