//! The applicant's PCS engine (inside the applicant's VTA, design §13 C7): a fresh `usk` per
//! application, registered under the community's current vetter period; the attestation request
//! a vetter answers; verification of every attestation on receipt (§13 C5); and the credential
//! request the community evaluates.
//!
//! # The applicant's reference
//!
//! `pcreds` gates attestations on `π_id`: an attester answers only a request `(id_Q, π_id)` that
//! proves knowledge of the key behind `id_Q`, under a session `ssid` and the attester's contact
//! name, so that nobody but the owner of `id_Q` learns the attester's (deterministic) tag for it.
//! In VTI the applicant's VTA makes its request once, when the application is created, before it
//! knows which vetters it will ask; and the applicant's client carries the same `id` to every
//! vetter (`vetting/request`, then `vta/pcs/attest`'s `applicantId`). So:
//!
//! - the reference the engine publishes ([`ApplicantEngine::reference`]) is
//!   `(vetter label, ssid, (id_Q, π_id))`, multibase ([`ApplicantRef`]), carried where the bare
//!   identifier used to be;
//! - `ssid` is fixed for the application (a digest of `id_Q`), and the contact name is the
//!   COMMUNITY'S DID rather than the vetter's. **This is weaker than the paper's `π_id`:** a
//!   request is bound to its application and community, not to one vetter, so anyone who holds
//!   a copy of it (any vetter it was sent to) can present it to another vetter of the same
//!   community. Binding it per vetter needs the applicant's VTA to make one request per vetter.
//! - `π_id` is computed with a nonce derived from the key and the session, so the reference is
//!   the same text every time it is asked for.

use predicate_credential_system::pcreds::{AttestationRequest, Backend};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use crate::{
    ProtoError,
    community::CommunityParams,
    meta::{ProofContext, StatementMeta, id_binding},
    scheme::{Bk, G1, Member, Usk, labelled_from_text, labelled_text, member, point_text, scalar_text},
    snapshot::{ApplicantSnapshot, HeldAttestation},
    verifier::Submission,
    vetter::HiddenAttestation,
};

/// An applicant's attestation request as it travels (module docs).
#[derive(Debug, Clone)]
pub struct ApplicantRef {
    /// The vetter label of the applicant's period: the helper key the request is under.
    pub label: String,
    pub ssid: Vec<u8>,
    pub request: AttestationRequest<Bk>,
}

impl ApplicantRef {
    /// The applicant's PCS identifier `id_Q`.
    pub fn id(&self) -> &G1 {
        &self.request.id
    }

    /// Multibase text, carried in `applicantId` and the `vetting/request` extension.
    ///
    /// # Errors
    /// [`ProtoError::Pcs`] if a value cannot be encoded.
    pub fn to_text(&self) -> Result<String, ProtoError> {
        labelled_text(&self.label, &(self.ssid.clone(), self.request.clone()))
    }

    /// The inverse of [`Self::to_text`], with validated decoding.
    ///
    /// # Errors
    /// [`ProtoError::Pcs`] or [`ProtoError::Serialization`] if the text does not decode.
    pub fn from_text(text: &str) -> Result<Self, ProtoError> {
        let (label, (ssid, request)) =
            labelled_from_text::<(Vec<u8>, AttestationRequest<Bk>)>(text)?;
        Ok(Self {
            label,
            ssid,
            request,
        })
    }
}

/// The session of an application's attestation request: fixed by its identifier.
fn request_ssid(id: &G1) -> Result<Vec<u8>, ProtoError> {
    let mut h = Sha256::new();
    h.update(b"openvtc/hidden-vetting/request/0.1\0");
    h.update(predicate_credential_system::serialization::to_bytes(id)?);
    Ok(h.finalize().to_vec())
}

pub struct ApplicantEngine {
    label: String,
    user: Member,
    pub join_did: String,
    held: Vec<HiddenAttestation>,
}

impl ApplicantEngine {
    /// A fresh `usk` for this application, registered under the community's current vetter
    /// period. The application lives in that period: its identifier is `Tag(usk, x_0)` at the
    /// identifier point of the period's helper key.
    ///
    /// # Errors
    /// [`ProtoError::PeriodNotLive`] if the community publishes no live period;
    /// [`ProtoError::Pcs`] if the key cannot be registered.
    pub fn new<R: RngCore + CryptoRng>(
        params: &CommunityParams,
        join_did: &str,
        rng: &mut R,
    ) -> Result<Self, ProtoError> {
        let usk = <Bk as Backend>::tag_keygen(params.pcreds().params(), rng);
        Self::with_key(params, join_did, &usk)
    }

    /// [`Self::new`], with the key derived from `seed` instead of drawn: how a VTA holds an
    /// applicant's key (design §13 C7). `seed` comes from the context's derivation base at a
    /// position used for this application alone (VTI-KEY-030), so the key never has to be
    /// stored and two applications never share one.
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn from_seed(
        params: &CommunityParams,
        join_did: &str,
        seed: &[u8; 32],
    ) -> Result<Self, ProtoError> {
        Self::new(params, join_did, &mut crate::scheme::seeded_rng(seed))
    }

    /// The engine for `usk` under the current period.
    fn with_key(params: &CommunityParams, join_did: &str, usk: &Usk) -> Result<Self, ProtoError> {
        let label = params.current_label()?.to_string();
        let user = member(params.pcreds(), params.hvk(&label)?, usk)?;
        Ok(Self {
            label,
            user,
            join_did: join_did.to_string(),
            held: Vec::new(),
        })
    }

    pub fn id(&self) -> &G1 {
        self.user.id()
    }

    /// The vetter label this application lives under.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The application's attestation request, as every vetter receives it (module docs). The
    /// same text every time.
    ///
    /// # Errors
    /// [`ProtoError::PeriodNotLive`] if the application's period is no longer live;
    /// [`ProtoError::Pcs`] if the proof cannot be made.
    pub fn reference(&self, params: &CommunityParams) -> Result<ApplicantRef, ProtoError> {
        let hvk = params.hvk(&self.label)?;
        let ssid = request_ssid(self.id())?;
        // A nonce derived from the key and the session (as RFC 6979 does for signatures): the
        // proof is the same on every call, and no two sessions share a nonce.
        let mut h = Sha256::new();
        h.update(b"openvtc/hidden-vetting/request-nonce/0.1\0");
        h.update(predicate_credential_system::serialization::to_bytes(self.user.expose_key())?);
        h.update(&ssid);
        h.update(params.community().as_bytes());
        let mut rng = ChaCha20Rng::from_seed(h.finalize().into());
        let request = params.pcreds().request_attestation(
            hvk,
            &self.user,
            &ssid,
            params.community().as_bytes(),
            &mut rng,
        )?;
        Ok(ApplicantRef {
            label: self.label.clone(),
            ssid,
            request,
        })
    }

    /// The storable form. Carries `usk`: see [`crate::snapshot`].
    pub fn snapshot(&self) -> Result<ApplicantSnapshot, ProtoError> {
        let mut snap =
            ApplicantSnapshot::new(self.user.expose_key(), &self.label, self.id(), &self.join_did)?;
        snap.held = self
            .held
            .iter()
            .map(HeldAttestation::of)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(snap)
    }

    /// Restore an application from storage, under the community's published parameters (its
    /// period must still be live).
    ///
    /// # Errors
    /// [`ProtoError::PeriodNotLive`] if the application's period is no longer live;
    /// [`ProtoError::Serialization`] if the stored identifier is not the key's.
    pub fn restore(snap: &ApplicantSnapshot, params: &CommunityParams) -> Result<Self, ProtoError> {
        let (usk, label, id, held) = snap.parts()?;
        let user = member(params.pcreds(), params.hvk(&label)?, &usk)?;
        if *user.id() != id {
            return Err(ProtoError::Serialization(
                "the stored identifier is not the stored key's".into(),
            ));
        }
        Ok(Self {
            label,
            user,
            join_did: snap.join_did.clone(),
            held,
        })
    }

    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// A metadata template the vetter completes; the token fields are the vetter's to fill.
    pub fn statement_meta(
        &self,
        params: &CommunityParams,
        requirements_digest: &str,
        base: StatementMeta,
    ) -> StatementMeta {
        StatementMeta {
            community: params.community().to_string(),
            requirements_digest: requirements_digest.to_string(),
            ..base
        }
    }

    /// Every check [`Self::receive`] makes, with no change to what is held.
    fn check(&self, params: &CommunityParams, att: &HiddenAttestation) -> Result<(), ProtoError> {
        if att.label != self.label {
            return Err(ProtoError::AttestationRejected(format!(
                "made under {}, not this application's {}",
                att.label, self.label
            )));
        }
        let hvk = params
            .hvk(&self.label)
            .map_err(|e| ProtoError::AttestationRejected(e.to_string()))?;
        let app = att.meta.context_bytes()?;
        params
            .pcreds()
            .check_attestation_in_context(hvk, self.id(), &att.attestation, &app)
            .map_err(|e| ProtoError::AttestationRejected(e.to_string()))?;
        if att.meta.token_label != att.token.label
            || att.meta.token_serial != scalar_text(&att.token.serial)?
        {
            return Err(ProtoError::AttestationRejected(
                "token does not match its statement".into(),
            ));
        }
        if !params.token_ok(&att.token)? {
            return Err(ProtoError::AttestationRejected(
                "token signature does not verify".into(),
            ));
        }
        Ok(())
    }

    /// Check an attestation on receipt, so `no-token` or a bad attestation shows up at the
    /// session and not at submit.
    ///
    /// # Errors
    /// [`ProtoError::AttestationRejected`] with the reason.
    pub fn receive(
        &mut self,
        params: &CommunityParams,
        att: HiddenAttestation,
    ) -> Result<(), ProtoError> {
        self.check(params, &att)?;
        self.held.push(att);
        Ok(())
    }

    /// Replace what a vetter vetted again: same tag, newer attestation. The new one is checked
    /// first, so one that fails leaves the old one held.
    ///
    /// # Errors
    /// As [`Self::receive`].
    pub fn replace(
        &mut self,
        params: &CommunityParams,
        att: HiddenAttestation,
    ) -> Result<(), ProtoError> {
        self.check(params, &att)?;
        let tag = att.attestation.tag;
        self.held.retain(|h| h.attestation.tag != tag);
        self.held.push(att);
        Ok(())
    }

    /// The held attestations [`Self::submit`] would carry under `params` as they stand: those
    /// whose token label is live, one per tag, while the application's period is live.
    fn usable_held(&self, params: &CommunityParams) -> Vec<&HiddenAttestation> {
        if params.hvk(&self.label).is_err() {
            return Vec::new();
        }
        let live = params.tokens().live_labels();
        let mut usable: Vec<&HiddenAttestation> = Vec::new();
        for h in &self.held {
            if live.contains(&h.token.label)
                && !usable
                    .iter()
                    .any(|u| u.attestation.tag == h.attestation.tag)
            {
                usable.push(h);
            }
        }
        usable
    }

    /// How many held attestations [`Self::submit`] would carry under `params` as they stand.
    ///
    /// # Errors
    /// Never, today; kept fallible for the callers written against the earlier engine.
    pub fn usable(&self, params: &CommunityParams) -> Result<usize, ProtoError> {
        Ok(self.usable_held(params).len())
    }

    /// The metadata of every held attestation, in the order received.
    #[must_use]
    pub fn held_meta(&self) -> Vec<StatementMeta> {
        self.held.iter().map(|h| h.meta.clone()).collect()
    }

    /// Build the submission from every held attestation that is still usable.
    ///
    /// # Errors
    /// [`ProtoError::PeriodNotLive`] if the application's period is no longer live;
    /// [`ProtoError::Pcs`] if the request cannot be made.
    pub fn submit<R: RngCore + CryptoRng>(
        &self,
        params: &CommunityParams,
        requirements_digest: &str,
        challenge: &str,
        rng: &mut R,
    ) -> Result<Submission, ProtoError> {
        let usable = self.usable_held(params);
        self.submit_attestations(params, requirements_digest, challenge, &usable, rng)
    }

    /// The submission over exactly `usable`, in order and unchecked: a `pcreds` credential
    /// request under the session `ssid = challenge`, bound to the metadata of every statement and
    /// to the proof context. The community only evaluates it and never answers it with a
    /// credential (design §13 C4), so the issuance state is dropped. [`Self::submit`] calls it
    /// with the usable held attestations; tests call it as an ADVERSARY HOOK with others.
    #[doc(hidden)]
    pub fn submit_attestations<R: RngCore + CryptoRng>(
        &self,
        params: &CommunityParams,
        requirements_digest: &str,
        challenge: &str,
        usable: &[&HiddenAttestation],
        rng: &mut R,
    ) -> Result<Submission, ProtoError> {
        let atts: Vec<_> = usable.iter().map(|h| h.attestation.clone()).collect();
        let apps: Vec<Vec<u8>> = usable
            .iter()
            .map(|h| h.meta.context_bytes())
            .collect::<Result<_, _>>()?;
        let app_refs: Vec<&[u8]> = apps.iter().map(Vec::as_slice).collect();
        let id_text = point_text(self.id())?;
        let binding = id_binding(
            &id_text,
            params.community(),
            requirements_digest,
            &self.join_did,
        );
        let app0 = ProofContext {
            challenge: challenge.to_string(),
            audience: params.community().to_string(),
            join_did: self.join_did.clone(),
            id_binding: binding.clone(),
        }
        .context_bytes()?;
        let (request, _state) = params.pcreds().request_credential_in_context(
            params.hvk(&self.label)?,
            &self.user,
            atts,
            &app_refs,
            challenge.as_bytes(),
            &app0,
            rng,
        )?;
        Ok(Submission {
            label: self.label.clone(),
            join_did: self.join_did.clone(),
            id_binding: binding,
            challenge: challenge.to_string(),
            statements: usable
                .iter()
                .map(|h| (h.meta.clone(), h.token.clone()))
                .collect(),
            request,
        })
    }
}
