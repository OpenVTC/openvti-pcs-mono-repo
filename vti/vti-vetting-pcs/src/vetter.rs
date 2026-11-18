//! The vetter's PCS engine, i.e. what runs inside the vetter's VTA (design §13 C7): the `usk`,
//! one root credential per vetter period, the token bucket, attest, refresh and withdraw.
//! openvtc only drives these.
//!
//! One key, many periods: the vetter registers the same `usk` under each period's helper key
//! (`Protocol::register_reusing`), so its identifier and its tags differ, unlinkably, from one
//! period to the next. A VTA derives the key from a seed and never stores it (§13 C7); a key
//! that is ever recovered links the vetter's attestations of every period it held, which is the
//! price of not storing per-period keys (design §18.2 prefers a key per period).

use std::collections::BTreeMap;

use predicate_credential_system::{
    Error as PcsError,
    pcreds::{Attestation, Backend, Credential, IssuanceState, PendingAttestation},
    sigma::FSProof,
};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

#[cfg(any(test, feature = "harness"))]
use crate::vtc::Vtc;
use crate::{
    ProtoError,
    applicant::ApplicantRef,
    community::CommunityParams,
    issuer::{
        RootCredentialWire, RootRequestWire, TokenBatchRequestWire, TokenBatchWire,
        TokenRequestWire,
    },
    meta::StatementMeta,
    scheme::{
        Bk, Fr, G1, Member, Usk, enrolment_ssid, member, period_of, point_text, scalar_text,
        vetter_label,
    },
    snapshot::VetterSnapshot,
    token::{Reservation, TokenSpend, TokenWallet},
    verifier::withdraw_context,
};

/// The blinding state of an enrolment in flight.
///
/// Named here so a caller can hold one across a round trip without depending on the PCS crate
/// directly. It is useless without the community's answer and dangerous to keep past it.
pub type EnrolmentBlinding = IssuanceState<Bk>;

/// An attestation as the applicant receives it (`vetting/attestation/0.1`).
#[derive(Debug, Clone)]
pub struct HiddenAttestation {
    /// The vetter label whose helper key the attestation is under: the applicant's.
    pub label: String,
    pub attestation: Attestation<Bk>,
    pub meta: StatementMeta,
    pub token: TokenSpend,
}

/// A statement this vetter made, kept so that it can be attested again without a new session
/// (design §4.3).
#[derive(Debug, Clone)]
pub(crate) struct Logged {
    pub label: String,
    pub applicant: G1,
    pub meta: StatementMeta,
}

pub struct VetterEngine {
    pub member: String,
    usk: Usk,
    /// Root credentials by vetter label (`vetter/<period>`).
    creds: BTreeMap<String, Credential<Bk>>,
    wallet: TokenWallet,
    /// A limit below the community's drip, kept here and never sent anywhere (§5.1).
    pub personal_limit: Option<usize>,
    attested: usize,
    log: Vec<Logged>,
}

impl Drop for VetterEngine {
    fn drop(&mut self) {
        self.usk.zeroize();
    }
}

impl VetterEngine {
    #[cfg(any(test, feature = "harness"))]
    /// A vetter with a fresh key, against the in-process community object.
    pub fn new<R: RngCore + CryptoRng>(
        member: &str,
        vtc: &Vtc,
        rng: &mut R,
    ) -> Result<Self, ProtoError> {
        Self::enrol_new(member, &vtc.params()?, rng)
    }

    /// A vetter's key from a community's **published** parameters.
    ///
    /// `member` is the DID this vetter will sign its requests with. It is bound into the root
    /// request's session and into the opening proofs the token drip sends, and checked by the
    /// community against the signer, so it is not a display name and cannot be changed later
    /// without abandoning the wallet.
    ///
    /// # Errors
    ///
    /// Never, today; kept fallible for a key generation that can refuse.
    pub fn enrol_new<R: RngCore + CryptoRng>(
        member: &str,
        params: &CommunityParams,
        rng: &mut R,
    ) -> Result<Self, ProtoError> {
        let usk = <Bk as Backend>::tag_keygen(params.pcreds().params(), rng);
        Ok(Self::with_key(member, usk))
    }

    /// [`Self::enrol_new`], with the key derived from `seed` instead of drawn: how a VTA holds a
    /// vetter's key (design §13 C7). `seed` is derived from the context's derivation base
    /// (VTI-KEY-030), so the same seed always gives the same `usk` — the key never has to be
    /// stored.
    ///
    /// # Errors
    ///
    /// As [`Self::enrol_new`].
    pub fn enrol_from_seed(
        member: &str,
        params: &CommunityParams,
        seed: &[u8; 32],
    ) -> Result<Self, ProtoError> {
        Self::enrol_new(member, params, &mut crate::scheme::seeded_rng(seed))
    }

    fn with_key(member: &str, usk: Usk) -> Self {
        Self {
            member: member.to_string(),
            usk,
            creds: BTreeMap::new(),
            wallet: TokenWallet::new(),
            personal_limit: None,
            attested: 0,
            log: Vec::new(),
        }
    }

    /// The vetter as a user of `label`'s helper key.
    fn user(&self, params: &CommunityParams, label: &str) -> Result<Member, ProtoError> {
        member(params.pcreds(), params.hvk(label)?, &self.usk)
    }

    /// The vetter's identifier under `label` (`vetter/<period>`), a live label of `params`.
    ///
    /// # Errors
    /// [`ProtoError::PeriodNotLive`] if the label is not live.
    pub fn id(&self, params: &CommunityParams, label: &str) -> Result<G1, ProtoError> {
        Ok(*self.user(params, label)?.id())
    }

    /// The labels this vetter holds a credential under, newest first.
    #[must_use]
    pub fn enrolled_labels(&self) -> Vec<String> {
        let mut labels: Vec<String> = self.creds.keys().cloned().collect();
        labels.sort_unstable_by(|a, b| b.cmp(a));
        labels
    }

    /// The storable form. Carries `usk`, the key every tag of this vetter derives from: see
    /// [`crate::snapshot`].
    pub fn snapshot(&self) -> Result<VetterSnapshot, ProtoError> {
        let mut snap = VetterSnapshot::new(&self.member, &self.usk)?;
        for (label, cred) in &self.creds {
            snap.put_credential(label, cred)?;
        }
        snap.tokens = self.wallet.snapshot()?;
        snap.pending = self.wallet.pending_snapshot()?;
        snap.personal_limit = self.personal_limit;
        for logged in &self.log {
            snap.record(logged)?;
        }
        Ok(snap)
    }

    /// Restore a vetter's engine from storage.
    ///
    /// # Errors
    /// [`ProtoError::Pcs`] or [`ProtoError::Serialization`] if a stored value does not decode.
    pub fn restore(snap: &VetterSnapshot) -> Result<Self, ProtoError> {
        let mut engine = Self::with_key(&snap.member, snap.key()?);
        for label in snap.credentials.keys() {
            if let Some(c) = snap.credential(label)? {
                engine.creds.insert(label.clone(), c);
            }
        }
        engine.log = snap.logged()?;
        engine.wallet = TokenWallet::restore(&snap.tokens)?;
        engine.wallet.restore_pending(&snap.pending)?;
        engine.personal_limit = snap.personal_limit;
        Ok(engine)
    }

    /// The vetter's half of enrolment under `period` (a bare period or its `vetter/` label): a
    /// blinded root request with no attestations, under the session the community rebuilds for
    /// this member, and the blinding state that unblinds what comes back.
    ///
    /// Split from [`Self::accept_enrolment`] because the two halves are a round trip in a
    /// deployment. The community sees a commitment; it never sees the credential it made.
    ///
    /// # Errors
    /// [`ProtoError::PeriodNotLive`] if the period is not live; [`ProtoError::Pcs`] if the
    /// request cannot be built.
    pub fn enrolment_request<R: RngCore + CryptoRng>(
        &self,
        params: &CommunityParams,
        period: &str,
        rng: &mut R,
    ) -> Result<(RootRequestWire, EnrolmentBlinding), ProtoError> {
        let period = period_of(period);
        let label = vetter_label(period);
        let user = self.user(params, &label)?;
        let ssid = enrolment_ssid(params.community(), &self.member, period);
        let (request, state) = params.pcreds().request_credential(
            params.hvk(&label)?,
            &user,
            Vec::new(),
            &ssid,
            rng,
        )?;
        Ok((RootRequestWire::of(&label, &request)?, state))
    }

    /// Unblind the community's answer into this vetter's credential for its label.
    ///
    /// # Errors
    /// [`ProtoError::Serialization`] if the answer cannot be decoded, [`ProtoError::Pcs`] if it
    /// does not unblind under the published key — which is what a wrong or swapped answer looks
    /// like from here.
    pub fn accept_enrolment(
        &mut self,
        params: &CommunityParams,
        answer: &RootCredentialWire,
        state: EnrolmentBlinding,
    ) -> Result<(), ProtoError> {
        let label = vetter_label(period_of(&answer.label));
        let user = self.user(params, &label)?;
        let pre = crate::scheme::dec(&answer.pre_credential)?;
        let cred = params
            .pcreds()
            .unblind(params.hvk(&label)?, &user, &pre, state)?;
        self.creds.insert(label, cred);
        Ok(())
    }

    /// The vetter's half of one scheduled drip fetch: `r` blinded serials for `tick`.
    ///
    /// Unconditional by design (§5.1) — a vetter asks on its schedule whether or not it has
    /// vetted anyone, because a fetch that tracked activity would report activity.
    ///
    /// # Errors
    /// [`ProtoError::LabelNotLive`] if `label` is not live; [`ProtoError::Pcs`] if a request
    /// cannot be built.
    pub fn drip_request<R: RngCore + CryptoRng>(
        &mut self,
        params: &CommunityParams,
        tick: u32,
        label: &str,
        r: usize,
        rng: &mut R,
    ) -> Result<TokenBatchRequestWire, ProtoError> {
        let tvk = params
            .tokens()
            .tvk(label)
            .ok_or_else(|| ProtoError::LabelNotLive(label.to_string()))?
            .clone();
        let reqs = self
            .wallet
            .prepare(&tvk, label, &self.member, tick, r, rng)?;
        Ok(TokenBatchRequestWire {
            label: label.to_string(),
            tick,
            requests: reqs
                .iter()
                .map(TokenRequestWire::of)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    /// Take a served batch into the wallet, and drop anything whose label has closed.
    ///
    /// # Errors
    /// [`ProtoError::Serialization`] if a token cannot be decoded, [`ProtoError::Pcs`] if one
    /// does not verify under the published token key.
    pub fn accept_drip(
        &mut self,
        params: &CommunityParams,
        served: &TokenBatchWire,
    ) -> Result<usize, ProtoError> {
        let tvk = params
            .tokens()
            .tvk(&served.label)
            .ok_or_else(|| ProtoError::LabelNotLive(served.label.clone()))?
            .clone();
        let pres = served
            .pre_credentials
            .iter()
            .map(|p| crate::scheme::dec(p))
            .collect::<Result<Vec<_>, _>>()?;
        self.wallet
            .receive(&tvk, &served.label, served.tick, &pres)?;
        self.wallet.expire(params.tokens().live_labels());
        Ok(pres.len())
    }

    #[cfg(any(test, feature = "harness"))]
    /// Root request for the community's current period. The two halves above, against the
    /// in-process community object.
    pub fn enroll<R: RngCore + CryptoRng>(
        &mut self,
        vtc: &mut Vtc,
        rng: &mut R,
    ) -> Result<(), ProtoError> {
        let period = vtc.current_period().to_string();
        let params = vtc.params()?;
        let (wire, state) = self.enrolment_request(&params, &period, rng)?;
        let (_, request) = wire.parse()?;
        let pre = vtc.issue_vetter_root(&self.member, &request, rng)?;
        self.accept_enrolment(
            &params,
            &RootCredentialWire {
                label: wire.label.clone(),
                pre_credential: crate::scheme::enc(&pre)?,
            },
            state,
        )
    }

    #[cfg(any(test, feature = "harness"))]
    /// One scheduled drip fetch: unconditional, `r` tokens. The two halves above, against the
    /// in-process community object.
    pub fn drip<R: RngCore + CryptoRng>(
        &mut self,
        vtc: &mut Vtc,
        tick: u32,
        label: &str,
        r: usize,
        rng: &mut R,
    ) -> Result<(), ProtoError> {
        let params = vtc.params()?;
        let batch = self.drip_request(&params, tick, label, r, rng)?;
        let reqs = batch
            .requests
            .iter()
            .map(|r| r.to_request())
            .collect::<Result<Vec<_>, _>>()?;
        let pres = vtc.drip(&self.member, tick, label, &reqs, rng)?;
        self.accept_drip(
            &params,
            &TokenBatchWire {
                label: label.to_string(),
                tick,
                pre_credentials: pres
                    .iter()
                    .map(crate::scheme::enc)
                    .collect::<Result<Vec<_>, _>>()?,
            },
        )?;
        Ok(())
    }

    #[cfg(any(test, feature = "harness"))]
    /// Tokens whose label closed are gone, and so are the credentials of periods that are no
    /// longer live. The log of statements stays, for refreshes.
    pub fn expire(&mut self, vtc: &Vtc) {
        self.wallet.expire(vtc.token_verifier().live_labels());
        let live: Vec<String> = vtc.live_periods().iter().map(|p| vetter_label(p)).collect();
        self.creds.retain(|label, _| live.contains(label));
    }

    pub fn tokens_held(&self) -> usize {
        self.wallet.held()
    }

    pub fn tokens_free(&self) -> usize {
        self.wallet.free()
    }

    /// Drop the draw in flight for `(label, tick)`: the community refused it.
    pub fn forget_draw(&mut self, label: &str, tick: u32) {
        self.wallet.forget(label, tick);
    }

    /// The draws asked for and not yet answered, as `(label, tick)`.
    #[must_use]
    pub fn draws_in_flight(&self) -> Vec<(String, u32)> {
        self.wallet.in_flight()
    }

    /// Accepting a `vetting/request` reserves a token (§5.2), or declines `atCapacity`.
    ///
    /// # Errors
    /// [`ProtoError::AtCapacity`] if no token is free or the personal limit is reached.
    pub fn accept(
        &mut self,
        prefer_label: Option<&str>,
        next_tick: u32,
    ) -> Result<Reservation, ProtoError> {
        if self.personal_limit.is_some_and(|l| self.attested >= l) {
            return Err(ProtoError::AtCapacity {
                available_from: next_tick,
            });
        }
        self.wallet
            .reserve(prefer_label)
            .ok_or(ProtoError::AtCapacity {
                available_from: next_tick,
            })
    }

    pub fn decline(&mut self, r: &Reservation) {
        self.wallet.release(r);
    }

    /// The applicant's `π_id`, checked under the applicant's period and the community's contact
    /// name ([`crate::applicant`], "The applicant's reference"), before any token is spent.
    fn receive(
        &self,
        params: &CommunityParams,
        applicant: &ApplicantRef,
    ) -> Result<PendingAttestation<Bk>, ProtoError> {
        if !self.creds.contains_key(&applicant.label) {
            return Err(ProtoError::NoCredentialForPeriod(applicant.label.clone()));
        }
        Ok(params.pcreds().receive_attestation_request(
            params.hvk(&applicant.label)?,
            &applicant.request,
            &applicant.ssid,
            params.community().as_bytes(),
        )?)
    }

    /// The attestation, bound to `meta` completed with the token's label and serial. Fallible,
    /// and touches no state.
    fn sign<R: RngCore + CryptoRng>(
        &self,
        params: &CommunityParams,
        applicant: &ApplicantRef,
        token_label: &str,
        token_serial: &Fr,
        mut meta: StatementMeta,
        rng: &mut R,
    ) -> Result<(Attestation<Bk>, StatementMeta), ProtoError> {
        let pending = self.receive(params, applicant)?;
        meta.token_label = token_label.to_string();
        meta.token_serial = scalar_text(token_serial)?;
        let app = meta.context_bytes()?;
        let user = self.user(params, &applicant.label)?;
        let attestation = params.pcreds().attest_in_context(
            params.hvk(&applicant.label)?,
            &user,
            &self.creds[&applicant.label],
            pending,
            &app,
            rng,
        )?;
        Ok((attestation, meta))
    }

    /// Infallible: count and log a signed attestation.
    fn record(
        &mut self,
        applicant: &ApplicantRef,
        attestation: Attestation<Bk>,
        meta: StatementMeta,
        token: TokenSpend,
    ) -> HiddenAttestation {
        self.attested += 1;
        self.log.push(Logged {
            label: applicant.label.clone(),
            applicant: *applicant.id(),
            meta: meta.clone(),
        });
        HiddenAttestation {
            label: applicant.label.clone(),
            attestation,
            meta,
            token,
        }
    }

    /// Attest for `applicant` after the human check: check its `π_id` under the applicant's
    /// period, bind the reserved token's serial and the statement metadata into the
    /// attestation's context, attest with this vetter's credential of that period, and only then
    /// spend the token, so that a failed attestation leaves it reserved, not lost.
    ///
    /// # Errors
    /// [`ProtoError::NoCredentialForPeriod`] if the vetter holds no credential for the
    /// applicant's period; [`ProtoError::Pcs`] if `π_id` does not verify or the attestation
    /// cannot be made.
    pub fn attest<R: RngCore + CryptoRng>(
        &mut self,
        params: &CommunityParams,
        reservation: &Reservation,
        applicant: &ApplicantRef,
        meta: StatementMeta,
        rng: &mut R,
    ) -> Result<HiddenAttestation, ProtoError> {
        let (attestation, meta) = self.sign(
            params,
            applicant,
            &reservation.label,
            &reservation.serial,
            meta,
            rng,
        )?;
        let token = self.wallet.spend(reservation, rng)?;
        Ok(self.record(applicant, attestation, meta, token))
    }

    /// ADVERSARY HOOK for tests: attest with a token of the caller's choosing, e.g. one already
    /// spent. An honest engine never does this; the community's spent set is what stops it.
    #[doc(hidden)]
    pub fn attest_with_token<R: RngCore + CryptoRng>(
        &mut self,
        params: &CommunityParams,
        token: TokenSpend,
        applicant: &ApplicantRef,
        meta: StatementMeta,
        rng: &mut R,
    ) -> Result<HiddenAttestation, ProtoError> {
        let (attestation, meta) =
            self.sign(params, applicant, &token.label, &token.serial, meta, rng)?;
        Ok(self.record(applicant, attestation, meta, token))
    }

    /// Refresh: the statement this vetter made for the applicant `previous`, attested again for
    /// `applicant` with a fresh token and no new human check (design §4.3).
    ///
    /// Within one period `applicant` is the same application and the tag is the same. After a
    /// rotation the applicant has registered again under the new period, with a new identifier,
    /// so the refreshed attestation has a new tag: tags under different helper keys are
    /// unlinkable, which is why a request never mixes periods, and so why one vetter cannot count
    /// twice in one.
    ///
    /// # Errors
    /// [`ProtoError::NoSuchStatement`] if this vetter made no statement for `previous`, and
    /// those of [`Self::attest`].
    pub fn refresh<R: RngCore + CryptoRng>(
        &mut self,
        params: &CommunityParams,
        previous: &G1,
        applicant: &ApplicantRef,
        rng: &mut R,
    ) -> Result<HiddenAttestation, ProtoError> {
        let meta = self
            .log
            .iter()
            .rev()
            .find(|l| l.applicant == *previous)
            .map(|l| l.meta.clone())
            .ok_or(ProtoError::NoSuchStatement)?;
        let reservation = self.accept(None, 0)?;
        match self.attest(params, &reservation, applicant, meta, rng) {
            Ok(att) => {
                self.attested -= 1; // a refresh is not a new vetting
                Ok(att)
            }
            Err(e) => {
                // `attest` spends the token only once the attestation is made, so it is still
                // reserved here and goes back to the free pool.
                self.wallet.release(&reservation);
                Err(e)
            }
        }
    }

    /// Withdraw one statement: the tag `t = Tag(usk, x_Q)` at the applicant's recipient point
    /// under `label`, and a proof of knowledge of the key behind it that does not link to this
    /// vetter's identifier (§4.4).
    ///
    /// # Errors
    /// [`ProtoError::PeriodNotLive`] if `label` is not live; [`ProtoError::Pcs`] if the tag is
    /// undefined or the proof cannot be made.
    pub fn withdraw<R: RngCore + CryptoRng>(
        &self,
        params: &CommunityParams,
        label: &str,
        applicant_id: &G1,
        rng: &mut R,
    ) -> Result<(G1, FSProof<Fr>), ProtoError> {
        let hvk = params.hvk(label)?;
        let pp = params.pcreds().params();
        let xq = params.pcreds().recipient_point(hvk.vk(), applicant_id)?;
        let tag = <Bk as Backend>::tag(pp, &self.usk, &xq).ok_or(PcsError::UndefinedTag)?;
        let ctx = withdraw_context(params.community(), label, &point_text(applicant_id)?);
        let proof = <Bk as Backend>::prove_tag(pp, &tag, &xq, &self.usk, &ctx, rng)?;
        Ok((tag, proof))
    }
}
