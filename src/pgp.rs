use std::io::Read;
use std::path::Path;

extern crate sequoia_openpgp as openpgp;
use openpgp::cert::{Cert, CertParser};
use openpgp::parse::stream::{MessageLayer, MessageStructure, VerificationHelper, VerifierBuilder};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;

#[derive(Clone)]
pub struct Verificator {
    certs_: Vec<Cert>,
}

impl<'a> Parse<'a, Verificator> for Verificator {
    fn from_reader<R: 'a + Read + Send + Sync>(reader: R) -> Result<Verificator, anyhow::Error> {
        let mut certs = Vec::new();
        for cert in CertParser::from_reader(reader)? {
            match cert {
                Ok(c) => certs.push(c),
                Err(err) => return Err(err),
            }
        }
        Ok(Verificator { certs_: certs })
    }
}

impl VerificationHelper for &Verificator {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(self.certs())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure.into_iter() {
            match layer {
                MessageLayer::SignatureGroup { results } => match results.into_iter().next() {
                    Some(Ok(_)) => return Ok(()),
                    Some(Err(e)) => return Err(openpgp::Error::from(e).into()),
                    None => return Err(anyhow::anyhow!("No signature")),
                },
                _ => {}
            }
        }

        Err(anyhow::anyhow!("signature verification failed"))
    }
}

impl Verificator {
    fn verify_builder(&self, builder: VerifierBuilder) -> openpgp::Result<()> {
        let policy = StandardPolicy::new();

        builder.with_policy(&policy, None, self)?;

        Ok(())
    }

    pub fn verify_bytes(&self, signed_message: &[u8]) -> openpgp::Result<()> {
        self.verify_builder(VerifierBuilder::from_bytes(signed_message)?)
    }

    pub fn verify_file<P: AsRef<Path>>(&self, path: P) -> openpgp::Result<()> {
        self.verify_builder(VerifierBuilder::from_file(path)?)
    }

    pub fn certs(&self) -> Vec<Cert> {
        self.certs_.iter().map(|cert| cert.clone()).collect()
    }
}
