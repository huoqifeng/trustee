// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use async_trait;

#[derive(Default)]
pub struct FakeSeAttest {}

#[async_trait::async_trait]
pub trait SeFakeVerifier {
    async fn create(
        &self,
        hkdFiles: Vec<String>,
        certFile: &String,
        signingFile: &String,
        arpkFile: &String
    ) -> Result<Vec<u8>>;

    async fn verify(
        &self,
        evidence: Vec<u8>,
        arpkFile: &String,
        hdr: Vec<u8>
    ) -> Result<Vec<u8>>;
}

#[async_trait::async_trait]
impl SeFakeVerifier for FakeSeAttest {
    async fn create(
        &self,
        hkdFiles: Vec<String>,
        certFile: &String,
        signingFile: &String,
        arpkFile: &String
    ) -> Result<Vec<u8>> {
        Result::Ok(Vec::new())
    }

    async fn verify(
        &self,
        evidence: Vec<u8>,
        arpkFile: &String,
        hdr: Vec<u8>
    ) -> Result<Vec<u8>> {
        Result::Ok(Vec::new())
    }
}