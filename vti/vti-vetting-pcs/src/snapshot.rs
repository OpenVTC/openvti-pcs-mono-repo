//! Storable forms of the member-side engines.
//!
//! A VTA keeps these in its engine keyspace between calls, so an application survives a
//! restart: the applicant's attestations, the vetter's credentials and the tokens it holds.
//!
//! **These can carry secrets.** `usk` is the key every tag of its holder is derived from, so a
//! copy of a vetter's snapshot links every attestation that vetter ever made. A VTA derives the
//! key from a seed and stores the snapshot without it (design §13 C7); the field is here for a
//! client that runs the engine itself.
//!
//! Binary values travel as multibase base58btc over the crate's validated canonical encoding,
//! the same convention as `wire`. An attestation's text carries its vetter label with it
//! ([`crate::scheme::labelled_text`]), because under `pcreds` an attestation means something
//! only under the helper key of its period.

use std::collections::BTreeMap;

use predicate_credential_system::pcreds::{Attestation, Credential};
use serde::{Deserialize, Serialize};

pub use crate::token::{HeldToken, PendingToken};

use crate::{
    ProtoError,
    meta::StatementMeta,
    scheme::{Bk, E, Fr, G1, Usk, dec, enc, labelled_from_text, labelled_text},
    token::TokenSpend,
    vetter::{HiddenAttestation, Logged},
};

/// One attestation the applicant holds, with what it needs to present it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HeldAttestation {
    /// The attestation with its vetter label ([`labelled_text`]).
    pub attestation: String,
    pub meta: StatementMeta,
    pub token_label: String,
    pub token_serial: String,
    pub token_shown: String,
}

impl HeldAttestation {
    pub fn of(att: &HiddenAttestation) -> Result<Self, ProtoError> {
        Ok(Self {
            attestation: labelled_text(&att.label, &att.attestation)?,
            meta: att.meta.clone(),
            token_label: att.token.label.clone(),
            token_serial: enc(&att.token.serial)?,
            token_shown: enc(&att.token.shown)?,
        })
    }

    pub fn restore(&self) -> Result<HiddenAttestation, ProtoError> {
        let (label, attestation) = labelled_from_text::<Attestation<Bk>>(&self.attestation)?;
        Ok(HiddenAttestation {
            label,
            attestation,
            meta: self.meta.clone(),
            token: TokenSpend {
                label: self.token_label.clone(),
                serial: dec::<Fr>(&self.token_serial)?,
                shown: dec::<predicate_credential_system::pcreds::pairing::PSPair<E>>(
                    &self.token_shown,
                )?,
            },
        })
    }
}

/// The applicant's engine, stored. One per application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicantSnapshot {
    /// SECRET: the key the applicant's identifier and requests are built from.
    pub usk: String,
    /// The vetter label the application lives under.
    pub label: String,
    pub id: String,
    pub join_did: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub held: Vec<HeldAttestation>,
}

impl ApplicantSnapshot {
    pub fn new(usk: &Usk, label: &str, id: &G1, join_did: &str) -> Result<Self, ProtoError> {
        Ok(Self {
            usk: enc(usk)?,
            label: label.to_string(),
            id: enc(id)?,
            join_did: join_did.to_string(),
            held: Vec::new(),
        })
    }

    pub(crate) fn parts(
        &self,
    ) -> Result<(Usk, String, G1, Vec<HiddenAttestation>), ProtoError> {
        let held = self
            .held
            .iter()
            .map(HeldAttestation::restore)
            .collect::<Result<Vec<_>, _>>()?;
        Ok((
            dec::<Fr>(&self.usk)?,
            self.label.clone(),
            dec::<G1>(&self.id)?,
            held,
        ))
    }
}

/// One statement a vetter made, stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoggedStatement {
    pub label: String,
    pub applicant: String,
    pub meta: StatementMeta,
}

/// The vetter's engine, stored. One per community.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VetterSnapshot {
    pub member: String,
    /// SECRET, and the most sensitive value here: every tag this vetter has ever produced is
    /// derived from it. Empty in a snapshot stored without its key.
    pub usk: String,
    /// Root credentials by vetter label, e.g. `vetter/2026-10`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credentials: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tokens: Vec<HeldToken>,
    /// Draws asked for and not yet answered, so an answer still unblinds after the engine has
    /// been stored and restored. SECRET, as `tokens` is.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending: Vec<PendingToken>,
    /// A limit below the community's drip, kept locally and never sent anywhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub personal_limit: Option<usize>,
    /// What was attested, so a statement can be refreshed without a new session.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub log: Vec<LoggedStatement>,
}

impl VetterSnapshot {
    /// A snapshot with no key material, for the parts that read only its bookkeeping — which
    /// labels it holds a credential under, and how many tokens it has.
    ///
    /// Not `Default`: a snapshot without a key is not a vetter, and making one implicitly
    /// constructible would let that mistake compile.
    #[must_use]
    pub fn without_keys(member: &str) -> Self {
        Self {
            member: member.to_string(),
            usk: String::new(),
            credentials: BTreeMap::new(),
            tokens: Vec::new(),
            pending: Vec::new(),
            personal_limit: None,
            log: Vec::new(),
        }
    }

    pub fn new(member: &str, usk: &Usk) -> Result<Self, ProtoError> {
        let mut snap = Self::without_keys(member);
        snap.usk = enc(usk)?;
        Ok(snap)
    }

    /// The same snapshot without its key: what a VTA stores.
    #[must_use]
    pub fn without_key(&self) -> Self {
        let mut snap = self.clone();
        snap.usk = String::new();
        snap
    }

    /// The same snapshot with `usk` put back: what a VTA restores from.
    ///
    /// # Errors
    /// [`ProtoError::Pcs`] if the key cannot be encoded.
    pub fn with_key(&self, usk: &Usk) -> Result<Self, ProtoError> {
        let mut snap = self.clone();
        snap.usk = enc(usk)?;
        Ok(snap)
    }

    pub(crate) fn key(&self) -> Result<Usk, ProtoError> {
        dec::<Fr>(&self.usk)
    }

    pub(crate) fn credential(&self, label: &str) -> Result<Option<Credential<Bk>>, ProtoError> {
        self.credentials
            .get(label)
            .map(|c| dec::<Credential<Bk>>(c))
            .transpose()
    }

    pub(crate) fn put_credential(
        &mut self,
        label: &str,
        cred: &Credential<Bk>,
    ) -> Result<(), ProtoError> {
        self.credentials.insert(label.to_string(), enc(cred)?);
        Ok(())
    }

    pub(crate) fn record(&mut self, logged: &Logged) -> Result<(), ProtoError> {
        self.log.push(LoggedStatement {
            label: logged.label.clone(),
            applicant: enc(&logged.applicant)?,
            meta: logged.meta.clone(),
        });
        Ok(())
    }

    pub(crate) fn logged(&self) -> Result<Vec<Logged>, ProtoError> {
        self.log
            .iter()
            .map(|l| {
                Ok(Logged {
                    label: l.label.clone(),
                    applicant: dec::<G1>(&l.applicant)?,
                    meta: l.meta.clone(),
                })
            })
            .collect()
    }
}
