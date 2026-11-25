#![cfg(all(feature = "alloc", any(feature = "ring", feature = "aws-lc-rs")))]

use core::time::Duration;

use pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject};
use webpki::{EndEntityCert, Error, KeyUsage, anchor_from_trusted_cert};

const ROOT: &[u8] = include_bytes!("long_chain/ca.pem");
const NINE: &[u8] = include_bytes!("long_chain/chain-9.pem");
const SIXTEEN: &[u8] = include_bytes!("long_chain/chain-16.pem");

fn certificates(pem: &'static [u8]) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(pem)
        .map(Result::unwrap)
        .collect()
}

fn verify(
    chain: &[CertificateDer<'_>],
    root: &CertificateDer<'_>,
    usage: KeyUsage,
) -> Result<(), Error> {
    let anchors = [anchor_from_trusted_cert(root)?];
    EndEntityCert::try_from(&chain[0])?
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &chain[1..],
            UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000)),
            usage,
            None,
            None,
        )
        .map(|_| ())
}

#[test]
fn long_chains_validate_for_server_and_client_auth() {
    let root = certificates(ROOT).remove(0);
    for pem in [NINE, SIXTEEN] {
        let chain = certificates(pem);
        verify(&chain, &root, KeyUsage::server_auth()).unwrap();
        verify(&chain, &root, KeyUsage::client_auth()).unwrap();
    }
}

#[test]
fn long_chains_preserve_signatures_constraints_and_subject_names() {
    let root = certificates(ROOT).remove(0);
    let chain = certificates(NINE);
    let cert = EndEntityCert::try_from(&chain[0]).unwrap();
    cert.verify_is_valid_for_subject_name(&ServerName::try_from("localhost").unwrap())
        .unwrap();
    assert!(
        cert.verify_is_valid_for_subject_name(&ServerName::try_from("other.example").unwrap())
            .is_err()
    );

    let mut damaged = chain.clone();
    let mut issuer = damaged[4].to_vec();
    *issuer.last_mut().unwrap() ^= 1;
    damaged[4] = issuer.into();
    assert!(verify(&damaged, &root, KeyUsage::server_auth()).is_err());

    let mut restricted = chain;
    restricted[5] = certificates(include_bytes!("long_chain/restricted-ca.pem")).remove(0);
    assert!(verify(&restricted, &root, KeyUsage::server_auth()).is_err());
}
