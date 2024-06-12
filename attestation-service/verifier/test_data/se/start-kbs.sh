export RUST_LOG=debug
#export DEFAULT_SE_HOST_KEY_DOCUMENTS_ROOT="/root/src/trustee/attestation-service/verifier/test_data/se/data/hkds"
#export DEFAULT_SE_CERTIFICATES_ROOT="/root/src/trustee/attestation-service/verifier/test_data/se/data/certs"
#export DEFAULT_SE_CERTIFICATE_ROOT_CA="/root/src/trustee/attestation-service/verifier/test_data/se/data/DigiCertCA.crt"
#export DEFAULT_SE_CERTIFICATE_REVOCATION_LISTS_ROOT="/root/src/trustee/attestation-service/verifier/test_data/se/data/crls"
#export DEFAULT_SE_IMAGE_HEADER_FILE="/root/src/trustee/attestation-service/verifier/test_data/se/data/hdr.bin"
#export DEFAULT_SE_MEASUREMENT_ENCR_KEY_PRIVATE="/root/src/trustee/attestation-service/verifier/test_data/se/data/ec-key/encrypt_key.pem"
#export DEFAULT_SE_MEASUREMENT_ENCR_KEY_PUBLIC="/root/src/trustee/attestation-service/verifier/test_data/se/data/ec-key/encrypt_key.pub"
export SE_SKIP_CERTS_VERIFICATION="true"

/root/src/trustee/target/release/kbs --config-file /root/src/trustee/attestation-service/verifier/test_data/se/kbs-config-console.toml