//! The wire form of a hidden-vetting submission: what the applicant puts in
//! `JoinRequestSubmitBody.extensions` and what the VTC reads back (design §8).
//!
//! The applicant's VTA builds it (`vta/pcs/prove`) and the community reads it; both use this
//! module, and `tests/fixtures/submission.json` freezes the JSON (`tests/cross_repo_fixture.rs`).
//!
//! Under `pcreds` the `proof` member carries the credential request `(id_Q, att⃗, Ĉ, π_iss)` with
//! the vetter label of its period (`crate::scheme::labelled_text`); `id` repeats `id_Q`, and a
//! submission whose two disagree is refused.
//!
//! Binary values travel as multibase base58btc (`z…`) over the crate's validated canonical
//! encoding, the convention the rest of the stack uses for `proofValue`.

use predicate_credential_system::{
    pcreds::CredentialRequest,
    serialization::{from_bytes, from_multibase, to_bytes, to_multibase},
};
use serde::{Deserialize, Serialize};

use crate::{
    ProtoError,
    meta::StatementMeta,
    scheme::{Bk, Fr, labelled_from_text, labelled_text, point_text},
    token::TokenSpend,
    verifier::Submission,
};

/// The member of `extensions` this occupies. `extensions` is an open object on
/// `vtc/join-requests/submit/0.3`; a first-class `vettingProof` member of a later `submit` is
/// what the design asks for before this ships.
pub const EXTENSIONS_MEMBER: &str = "hiddenVetting";

/// The only suite this crate implements: `Σ-PS` with `Tag_DDH` over BLS12-381, run as `pcreds`
/// (`Π_PCreds`) with a helper key per vetter period. The name is the one the earlier, game-based
/// `pcs` construction used; nothing made under that construction verifies under this one.
pub const SUITE: &str = "ps-ddh-bls12381";

/// One statement as it travels: its public metadata and the token spent on it. The attestation
/// itself is inside `proof`, in the same order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatementWire {
    pub meta: StatementMeta,
    pub token: TokenWire,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TokenWire {
    pub label: String,
    /// The revealed serial.
    pub serial: String,
    /// The re-randomised signature on `serial` under the label's key.
    pub shown: String,
}

/// `extensions.hiddenVetting`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubmissionWire {
    pub suite: String,
    /// The applicant's PCS identifier.
    pub id: String,
    pub join_did: String,
    /// Stand-in for the join persona's Data Integrity proof over
    /// `(id, community, requirementsDigest)` (§4.2).
    pub id_binding: String,
    /// The VTC's single-use challenge, as issued.
    pub challenge: String,
    /// One per attestation of `proof`, in the same order.
    pub statements: Vec<StatementWire>,
    /// The `pcreds` credential request `(id_Q, att⃗, Ĉ, π_iss)`, which carries the attestations,
    /// with the vetter label of its period ([`labelled_text`]).
    pub proof: String,
}

impl TokenWire {
    pub fn from_spend(spend: &TokenSpend) -> Result<Self, ProtoError> {
        Ok(Self {
            label: spend.label.clone(),
            serial: to_multibase(&to_bytes(&spend.serial)?),
            shown: to_multibase(&to_bytes(&spend.shown)?),
        })
    }

    pub fn to_spend(&self) -> Result<TokenSpend, ProtoError> {
        Ok(TokenSpend {
            label: self.label.clone(),
            serial: from_bytes::<Fr>(&from_multibase(&self.serial)?)?,
            shown: from_bytes(&from_multibase(&self.shown)?)?,
        })
    }
}

impl SubmissionWire {
    /// The wire form of a submission the applicant's engine built.
    pub fn from_submission(sub: &Submission) -> Result<Self, ProtoError> {
        Ok(Self {
            suite: SUITE.to_string(),
            id: point_text(sub.id())?,
            join_did: sub.join_did.clone(),
            id_binding: sub.id_binding.clone(),
            challenge: sub.challenge.clone(),
            statements: sub
                .statements
                .iter()
                .map(|(meta, token)| {
                    Ok(StatementWire {
                        meta: meta.clone(),
                        token: TokenWire::from_spend(token)?,
                    })
                })
                .collect::<Result<_, ProtoError>>()?,
            proof: labelled_text(&sub.label, &sub.request)?,
        })
    }

    /// Decode. Every group element is validated on the way in (the crate's decoders refuse a
    /// point off the curve or outside the prime-order subgroup), and the suite must be one we
    /// implement.
    pub fn to_submission(&self) -> Result<Submission, ProtoError> {
        if self.suite != SUITE {
            return Err(ProtoError::Serialization(format!(
                "unknown suite {}, expected {SUITE}",
                self.suite
            )));
        }
        let (label, request): (String, CredentialRequest<Bk>) = labelled_from_text(&self.proof)?;
        if request.attestations.len() != self.statements.len() {
            return Err(ProtoError::CountMismatch {
                statements: self.statements.len(),
                attestations: request.attestations.len(),
            });
        }
        if point_text(&request.id)? != self.id {
            return Err(ProtoError::Serialization(
                "`id` is not the identifier the request is for".into(),
            ));
        }
        Ok(Submission {
            label,
            join_did: self.join_did.clone(),
            id_binding: self.id_binding.clone(),
            challenge: self.challenge.clone(),
            statements: self
                .statements
                .iter()
                .map(|s| Ok((s.meta.clone(), s.token.to_spend()?)))
                .collect::<Result<_, ProtoError>>()?,
            request,
        })
    }

    /// `extensions` as the submit body carries it: `{ "hiddenVetting": { … } }`.
    pub fn to_extensions(&self) -> Result<serde_json::Value, ProtoError> {
        let mut map = serde_json::Map::new();
        map.insert(
            EXTENSIONS_MEMBER.to_string(),
            serde_json::to_value(self).map_err(|e| ProtoError::Serialization(e.to_string()))?,
        );
        Ok(serde_json::Value::Object(map))
    }

    /// Read it back out of an `extensions` object; `Ok(None)` when the member is absent, which
    /// is every submission of a community that does not run hidden mode.
    pub fn from_extensions(extensions: &serde_json::Value) -> Result<Option<Self>, ProtoError> {
        let Some(value) = extensions.get(EXTENSIONS_MEMBER) else {
            return Ok(None);
        };
        serde_json::from_value(value.clone())
            .map(Some)
            .map_err(|e| ProtoError::Serialization(e.to_string()))
    }
}
