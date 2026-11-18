//! Verifying a hidden-vetting submission from PUBLIC data only, and turning it into the facts
//! VTI already counts (design §2).
//!
//! This half holds no secret: the helper keys it uses are the published `hvk` of each live
//! vetter period, the token keys the published `tvk` of each live label. The VTC service runs
//! it beside its own state.
//!
//! # Evaluation from public data
//!
//! A submission is a `pcreds` credential request `(id_Q, att⃗, Ĉ, π_iss)` under the session
//! `ssid = challenge`, with application contexts. `Protocol::evaluate_request` takes a
//! [`Helper`](predicate_credential_system::pcreds::Helper), which holds the helper's signing key
//! although evaluation reads only its public key. [`evaluate`] performs the same steps (protocol
//! box, `CredentialRequest`, the helper's steps (i) and (ii)) with the library's public checks
//! and nothing else: `id_Q ∈ T` at the identifier point of the period's key, `π_iss` under the
//! issuance context rebuilt from the request and the verifier's own copy of the contexts, and
//! each attestation under its own context ([`Pcreds::check_attestation_in_context`]). The
//! community never answers the request with a credential (design §13 C4).
//!
//! **THIS IS THE ONE THAT DECIDES.**

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, NaiveTime, Utc};
use predicate_credential_system::{
    pcreds::{Backend, CredentialRequest, IssuanceStatement},
    sigma::FSProof,
};
use serde::Serialize;
use vta_sdk::{
    protocols::vetting::{VettingMethod, VettingRelationship, VettingRequirements},
    vetting::requirements::{Evaluation, StatementFacts, evaluate as count},
};

use crate::{
    ProtoError,
    meta::{ProofContext, StatementMeta, id_binding},
    scheme::{Bk, CheckedHvk, Fr, G1, Hvk, Pcreds, pcreds, point_text, scalar_text},
    token::{SpendOutcome, TokenSpend, TokenVerifier},
};

/// The most attestations one submission may carry. Every attestation costs a pairing check, so
/// a submission is refused above this before any is verified.
pub const MAX_ATTESTATIONS: usize = 64;

/// The hidden-vetting part of a join submission (`extensions.hiddenVetting`, design §8).
#[derive(Debug, Clone)]
pub struct Submission {
    /// The vetter label of the applicant's period: the request is under its helper key.
    pub label: String,
    pub join_did: String,
    /// The binding of `id` to the join persona (§4.2), as the applicant computed it. The
    /// verifier recomputes it and compares; it never takes the applicant's word for it.
    pub id_binding: String,
    pub challenge: String,
    /// One per attestation of `request`, in the same order.
    pub statements: Vec<(StatementMeta, TokenSpend)>,
    /// `(id_Q, att⃗, Ĉ, π_iss)` under the session `ssid = challenge`.
    pub request: CredentialRequest<Bk>,
}

impl Submission {
    /// The applicant's PCS identifier.
    pub fn id(&self) -> &G1 {
        &self.request.id
    }
}

/// One row of `VettingFacts.statements`, as the VTC builds it today, with `issuer` = the tag.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatementRecord {
    pub id: String,
    pub issuer: String,
    pub verified: bool,
    pub eligible: bool,
    pub revoked: bool,
    pub method: VettingMethod,
    pub declared_relationship: VettingRelationship,
    pub counted: bool,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub evaluation: Evaluation,
    pub statements: Vec<StatementRecord>,
}

/// What the verifier keeps per statement of an application.
#[derive(Debug, Clone)]
pub(crate) struct Kept {
    pub facts: StatementFacts,
    pub tag: String,
    pub verified: bool,
    pub method: VettingMethod,
    pub relationship: VettingRelationship,
    pub failures: Vec<String>,
}

/// The published parameters a verifier needs, i.e. what a community's manifest carries.
pub struct VerifierParams {
    pub community: String,
    pub audience: String,
    pub requirements: VettingRequirements,
    pub requirements_digest: String,
}

/// `N''` of a credential request under `hvk`: the distinct tags of the attestations that verify,
/// in their order, after `id_Q ∈ T` and `π_iss` (module docs, "Evaluation from public data").
///
/// # Errors
/// [`ProtoError::ProofRejected`] if `id_Q` or `π_iss` does not verify; [`ProtoError::DuplicateTag`]
/// for two attestations with one tag; [`ProtoError::CountMismatch`] if `att_apps` does not hold
/// one context per attestation.
pub fn evaluate(
    pcreds: &Pcreds,
    hvk: &CheckedHvk,
    request: &CredentialRequest<Bk>,
    ssid: &[u8],
    att_apps: &[&[u8]],
    app: &[u8],
) -> Result<Vec<G1>, ProtoError> {
    if att_apps.len() != request.attestations.len() {
        return Err(ProtoError::CountMismatch {
            statements: att_apps.len(),
            attestations: request.attestations.len(),
        });
    }
    let pp = pcreds.params();
    // (i) id_Q ∈ T at x_0, and π_iss under (ssid, att⃗) and the contexts.
    <Bk as Backend>::check_tag(pp, &request.id, hvk.identifier_point(), "id_Q")
        .map_err(ProtoError::ProofRejected)?;
    let ctx = pcreds
        .issuance_context_in(
            hvk.vk(),
            ssid,
            &request.attestations,
            Some(att_apps),
            Some(app),
        )
        .map_err(ProtoError::ProofRejected)?;
    let statement = IssuanceStatement {
        vk: hvk.vk(),
        request: &request.request,
        id: &request.id,
        x0: hvk.identifier_point(),
    };
    <Bk as Backend>::check_issuance_proof(pp, &statement, &ctx, &request.proof)
        .map_err(ProtoError::ProofRejected)?;
    // (ii) N'': each attestation under its own context. One attestation per tag, so that N''
    // says exactly which attestations verified.
    let mut seen = HashSet::new();
    let mut valid = Vec::new();
    for (att, att_app) in request.attestations.iter().zip(att_apps) {
        if !seen.insert(point_text(&att.tag)?) {
            return Err(ProtoError::DuplicateTag);
        }
        if pcreds
            .check_attestation_in_context(hvk, &request.id, att, att_app)
            .is_ok()
        {
            valid.push(att.tag);
        }
    }
    Ok(valid)
}

pub struct Verifier {
    pub params: VerifierParams,
    pcreds: Pcreds,
    /// Live vetter labels, current first, each with its checked helper key.
    periods: Vec<(String, CheckedHvk)>,
    pub tokens: TokenVerifier,
    withdrawn: HashSet<(String, String)>,
    applications: HashMap<String, BTreeMap<String, Kept>>,
}

impl Verifier {
    /// From public parameters: the helper key of each live vetter label (current first), and
    /// the token verifier.
    ///
    /// # Errors
    /// [`ProtoError::Pcs`] if the deployment parameters cannot be derived, or a helper key is
    /// not one of its keys.
    pub fn new(
        params: VerifierParams,
        helper_keys: Vec<(String, Hvk)>,
        tokens: TokenVerifier,
    ) -> Result<Self, ProtoError> {
        let pcreds = pcreds(&params.community)?;
        let mut verifier = Self {
            params,
            pcreds,
            periods: Vec::new(),
            tokens,
            withdrawn: HashSet::new(),
            applications: HashMap::new(),
        };
        verifier.set_live_periods(helper_keys)?;
        Ok(verifier)
    }

    pub fn pcreds(&self) -> &Pcreds {
        &self.pcreds
    }
    /// The live vetter labels, current first.
    pub fn live_labels(&self) -> Vec<String> {
        self.periods.iter().map(|(l, _)| l.clone()).collect()
    }
    /// The checked helper key of a live vetter label.
    ///
    /// # Errors
    /// [`ProtoError::PeriodNotLive`] if the label is not live.
    pub fn hvk(&self, label: &str) -> Result<&CheckedHvk, ProtoError> {
        self.periods
            .iter()
            .find(|(l, _)| l == label)
            .map(|(_, k)| k)
            .ok_or_else(|| ProtoError::PeriodNotLive(label.to_string()))
    }

    /// Rotation and emergency drops both land here: the live periods are the ones given now.
    ///
    /// # Errors
    /// [`ProtoError::Pcs`] if a helper key is not a key of this deployment.
    pub fn set_live_periods(&mut self, helper_keys: Vec<(String, Hvk)>) -> Result<(), ProtoError> {
        self.periods = helper_keys
            .into_iter()
            .map(|(label, vk)| Ok((label, self.pcreds.helper_key(&vk)?)))
            .collect::<Result<_, ProtoError>>()?;
        Ok(())
    }

    /// Verify a submission, spend its tokens, and count. Records are kept per applicant `id`,
    /// so a resubmission after `requestMore` adds to what was already counted.
    ///
    /// The caller has already checked that the challenge is one it issued and unused.
    ///
    /// # Errors
    /// [`ProtoError::PeriodNotLive`] if the submission's period is not live;
    /// [`ProtoError::TooManyAttestations`], [`ProtoError::CountMismatch`],
    /// [`ProtoError::DuplicateTag`] for a malformed submission;
    /// [`ProtoError::AttestationRejected`] if the identifier binding does not match;
    /// [`ProtoError::ProofRejected`] if `id_Q` or `π_iss` does not verify.
    pub fn submit(&mut self, sub: &Submission, now: DateTime<Utc>) -> Result<Decision, ProtoError> {
        let attestations = &sub.request.attestations;
        if attestations.len() > MAX_ATTESTATIONS {
            return Err(ProtoError::TooManyAttestations {
                count: attestations.len(),
                max: MAX_ATTESTATIONS,
            });
        }
        if sub.statements.len() != attestations.len() {
            return Err(ProtoError::CountMismatch {
                statements: sub.statements.len(),
                attestations: attestations.len(),
            });
        }
        let id_text = point_text(sub.id())?;
        let binding = id_binding(
            &id_text,
            &self.params.community,
            &self.params.requirements_digest,
            &sub.join_did,
        );
        if sub.id_binding != binding {
            return Err(ProtoError::AttestationRejected(
                "the identifier binding does not match this community and join DID".into(),
            ));
        }
        let app0 = ProofContext {
            challenge: sub.challenge.clone(),
            audience: self.params.audience.clone(),
            join_did: sub.join_did.clone(),
            id_binding: binding,
        }
        .context_bytes()?;
        let apps: Vec<Vec<u8>> = sub
            .statements
            .iter()
            .map(|(m, _)| m.context_bytes())
            .collect::<Result<_, _>>()?;
        let app_refs: Vec<&[u8]> = apps.iter().map(Vec::as_slice).collect();
        let valid: HashSet<String> = evaluate(
            &self.pcreds,
            self.hvk(&sub.label)?,
            &sub.request,
            sub.challenge.as_bytes(),
            &app_refs,
            &app0,
        )?
        .iter()
        .map(point_text)
        .collect::<Result<_, _>>()?;

        // `π_iss` holds: the applicant owns `id`, and the request is bound to this challenge, to
        // the proof context and to the metadata of every statement, in order. A statement whose
        // tag is in `N''` is a valid attestation from a holder of a credential of the period,
        // bound to its metadata (including its token serial).
        for ((meta, spend), att) in sub.statements.iter().zip(attestations) {
            let tag = point_text(&att.tag)?;
            let verified = valid.contains(&tag);
            let mut failures = Vec::new();
            // The checks that need no token come first, so that a statement already ineligible
            // for them does not burn its token in the spent set.
            if meta.requirements_digest != self.params.requirements_digest {
                failures.push("requirements-digest-mismatch".to_string());
            }
            if now.date_naive() > meta.valid_until {
                failures.push("expired".to_string());
            }
            let mut eligible = verified && failures.is_empty();
            if !verified {
                failures.push("unverified".to_string());
            } else if !eligible {
                // Not spent: see above.
            } else if meta.token_label != spend.label
                || meta.token_serial != scalar_text(&spend.serial)?
            {
                failures.push("token-mismatch".to_string());
                eligible = false;
            } else if !self.tokens.signature_ok(spend)? {
                failures.push("no-token".to_string());
                eligible = false;
            } else if self.tokens.record_spend(spend, &id_text, &tag)? == SpendOutcome::DoubleSpend
            {
                failures.push("token-double-spend".to_string());
                eligible = false;
            }
            let facts = StatementFacts {
                statement_id: meta.digest()?,
                vetter: tag.clone(),
                method: meta.method,
                claims_verified: meta.claims_verified.clone(),
                document_classes: Vec::new(),
                declared_relationship: meta.declared_relationship,
                identity_commitment: meta.identity_commitment.clone(),
                valid_from: DateTime::from_naive_utc_and_offset(
                    meta.valid_from.and_time(NaiveTime::MIN),
                    Utc,
                ),
                community_matches: meta.community == self.params.community,
                eligible,
                revoked: false,
            };
            self.applications
                .entry(id_text.clone())
                .or_default()
                .insert(
                    facts.statement_id.clone(),
                    Kept {
                        facts,
                        tag,
                        verified,
                        method: meta.method,
                        relationship: meta.declared_relationship,
                        failures,
                    },
                );
        }
        Ok(self.evaluate(&id_text, now))
    }

    /// Count an application as it stands now (withdrawals included).
    pub fn evaluate(&self, id_text: &str, now: DateTime<Utc>) -> Decision {
        let kept: Vec<Kept> = self
            .applications
            .get(id_text)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        let facts: Vec<StatementFacts> = kept
            .iter()
            .map(|k| {
                let mut f = k.facts.clone();
                f.revoked = self
                    .withdrawn
                    .contains(&(id_text.to_string(), k.tag.clone()));
                f
            })
            .collect();
        let evaluation = count(&self.params.requirements, &facts, now);
        let statements = kept
            .iter()
            .zip(&facts)
            .map(|(k, f)| {
                let mut failures = k.failures.clone();
                if let Some((_, reasons)) = evaluation
                    .not_counted
                    .iter()
                    .find(|(id, _)| *id == f.statement_id)
                {
                    failures.extend(reasons.iter().map(|r| r.code().to_string()));
                }
                failures.dedup();
                StatementRecord {
                    id: f.statement_id.clone(),
                    issuer: k.tag.clone(),
                    verified: k.verified,
                    eligible: f.eligible,
                    revoked: f.revoked,
                    method: k.method,
                    declared_relationship: k.relationship,
                    counted: evaluation.counted.contains(&f.statement_id),
                    failures,
                }
            })
            .collect();
        Decision {
            evaluation,
            statements,
        }
    }

    /// Withdrawal of one statement by its tag (§4.4), for the applicant `id` of the vetter
    /// period `label`. The proof shows knowledge of the key behind the tag at the applicant's
    /// recipient point and nothing else, so the notice may come from a fresh sender (§13 C6).
    ///
    /// # Errors
    /// [`ProtoError::PeriodNotLive`] if `label` is not live.
    pub fn withdraw(
        &mut self,
        label: &str,
        id: &G1,
        tag: &G1,
        proof: &FSProof<Fr>,
    ) -> Result<bool, ProtoError> {
        let hvk = self.hvk(label)?;
        let pp = self.pcreds.params();
        let xq = self.pcreds.recipient_point(hvk.vk(), id)?;
        let id_text = point_text(id)?;
        let ctx = withdraw_context(&self.params.community, label, &id_text);
        if <Bk as Backend>::check_tag(pp, tag, &xq, "t").is_err()
            || <Bk as Backend>::check_tag_proof(pp, tag, &xq, &ctx, proof).is_err()
        {
            return Ok(false);
        }
        self.withdrawn.insert((id_text, point_text(tag)?));
        Ok(true)
    }
}

/// The context of a withdrawal proof: the community, the vetter label and the applicant.
pub fn withdraw_context(community: &str, label: &str, id_text: &str) -> Vec<u8> {
    let mut ctx = b"openvtc/hidden-vetting/withdraw/0.2\0".to_vec();
    for part in [community, label, id_text] {
        ctx.extend((part.len() as u64).to_le_bytes());
        ctx.extend(part.as_bytes());
    }
    ctx
}
