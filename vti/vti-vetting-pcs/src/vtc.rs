//! The community side: the PCS *helper*. It owns what the [`Verifier`] does not — the keys,
//! who holds a vetter grant, who was issued a credential under which period, and event mode —
//! and delegates every check on a submission to the verifier.
//!
//! In production this is `vtc-service` (VTI). This in-process copy is what the member-side
//! engines are tested against.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use predicate_credential_system::{pcreds::CredentialRequest, sigma::FSProof};
use rand::{CryptoRng, RngCore};
use vta_sdk::protocols::vetting::VettingRequirements;

use crate::{
    ProtoError,
    community::CommunityParams,
    issuer::{DripOrder, Issuer, PreCredential},
    scheme::{
        Bk, Fr, G1, Hvk, Pcreds, Tvk, event_token_label, monthly_token_label, period_of,
        point_text, vetter_label,
    },
    token::{TokenRequest, TokenVerifier},
    verifier::{Verifier, VerifierParams},
};

pub use crate::verifier::{
    Decision, MAX_ATTESTATIONS, StatementRecord, Submission, withdraw_context,
};

/// Three a tick unless the community says otherwise — the same default `vtc-service` carries.
pub const DEFAULT_DRIP_PER_TICK: usize = 3;

/// An event label's rate. Event mode exists because a vetter at a conference meets twenty
/// people in a day, and the ordinary drip would make them turn people away (§5.1); the point of
/// the separate label is that the higher rate ends with the event.
pub const DEFAULT_EVENT_DRIP_PER_TICK: usize = 20;

pub struct Vtc {
    pub community: String,
    /// Everything a submission is checked against: public parameters only.
    pub verifier: Verifier,
    /// The keys, and the signing they do. The same type `vtc-service` mints with.
    issuer: Issuer,
    /// Live vetter periods, current first.
    periods: Vec<String>,
    /// The published drip rate: the most this community signs for one vetter in one tick.
    drip_rate: usize,
    /// The rate under an event label, which is the reason event labels exist.
    event_drip_rate: usize,
    grants: HashSet<String>,
    /// `(member, period)` → the PCS identifier issued to: one root credential per member and
    /// period.
    issued: HashMap<(String, String), String>,
    current_token_label: String,
    events: HashMap<String, HashSet<String>>,
    challenges: HashSet<String>,
}

impl Vtc {
    pub fn new<R: RngCore + CryptoRng>(
        community: &str,
        period: &str,
        requirements: serde_json::Value,
        rng: &mut R,
    ) -> Result<Self, ProtoError> {
        let issuer = Issuer::generate(community, rng)?;
        let requirements_digest =
            vta_sdk::vetting::requirements::requirements_digest(&requirements)
                .map_err(|e| ProtoError::Serialization(e.to_string()))?;
        let requirements: VettingRequirements = serde_json::from_value(requirements)
            .map_err(|e| ProtoError::Serialization(e.to_string()))?;
        let current_token_label = monthly_token_label(period);
        let tokens = TokenVerifier::new([(
            current_token_label.clone(),
            issuer.tvk(&current_token_label),
        )]);
        let verifier = Verifier::new(
            VerifierParams {
                community: community.to_string(),
                audience: community.to_string(),
                requirements,
                requirements_digest,
            },
            vec![(vetter_label(period), issuer.hvk(period))],
            tokens,
        )?;
        Ok(Self {
            community: community.to_string(),
            verifier,
            issuer,
            periods: vec![period.to_string()],
            drip_rate: DEFAULT_DRIP_PER_TICK,
            event_drip_rate: DEFAULT_EVENT_DRIP_PER_TICK,
            grants: HashSet::new(),
            issued: HashMap::new(),
            current_token_label,
            events: HashMap::new(),
            challenges: HashSet::new(),
        })
    }

    /// Set this community's drip rate. Published, and enforced on every tick.
    #[must_use]
    pub fn with_drip_rate(mut self, tokens_per_tick: usize) -> Self {
        self.drip_rate = tokens_per_tick;
        self
    }

    pub fn drip_rate(&self) -> usize {
        self.drip_rate
    }

    /// Set the rate an event label drips at.
    #[must_use]
    pub fn with_event_drip_rate(mut self, tokens_per_tick: usize) -> Self {
        self.event_drip_rate = tokens_per_tick;
        self
    }

    pub fn event_drip_rate(&self) -> usize {
        self.event_drip_rate
    }

    /// The rate that applies to `label`: the event rate for an event label, the ordinary drip
    /// otherwise.
    pub fn quota_for(&self, label: &str) -> usize {
        if label.starts_with("token/event/") {
            self.event_drip_rate
        } else {
            self.drip_rate
        }
    }

    // --- public parameters, as the manifest's `vetting.ext` carries them --------------------

    pub fn pcreds(&self) -> &Pcreds {
        self.verifier.pcreds()
    }
    /// The scheme instance, by its earlier name.
    pub fn open(&self) -> &Pcreds {
        self.verifier.pcreds()
    }
    /// The helper key of a period (bare, or its `vetter/` label).
    pub fn hvk(&self, period: &str) -> Hvk {
        self.issuer.hvk(period)
    }
    /// The token key of a live label.
    pub fn tvk(&self, label: &str) -> Option<&Tvk> {
        self.verifier.tokens.tvk(label)
    }
    /// The live vetter periods, current first.
    pub fn live_periods(&self) -> &[String] {
        &self.periods
    }
    pub fn current_period(&self) -> &str {
        &self.periods[0]
    }
    pub fn is_live(&self, period: &str) -> bool {
        self.periods.iter().any(|p| p == period_of(period))
    }
    pub fn current_token_label(&self) -> &str {
        &self.current_token_label
    }
    pub fn requirements_digest(&self) -> &str {
        &self.verifier.params.requirements_digest
    }
    pub fn audience(&self) -> &str {
        &self.verifier.params.audience
    }

    /// What this community publishes: the same view a member works from, so a test drives the
    /// code path a client does (`vetting.ext` of the manifest, design §8).
    ///
    /// # Errors
    /// [`ProtoError::Pcs`] if the deployment parameters cannot be re-derived.
    pub fn params(&self) -> Result<CommunityParams, ProtoError> {
        let token_labels: Vec<String> = self
            .token_verifier()
            .live_labels()
            .iter()
            .cloned()
            .collect();
        CommunityParams::new(
            &self.community,
            self.periods.iter().map(|p| self.issuer.hvk(p)).collect(),
            token_labels.iter().map(|l| self.issuer.tvk(l)).collect(),
            self.periods.iter().map(|p| vetter_label(p)).collect(),
            token_labels,
            self.drip_rate,
        )
    }

    /// The token side of the public parameters, and the spent set.
    pub fn token_verifier(&self) -> &TokenVerifier {
        &self.verifier.tokens
    }

    fn sync_verifier(&mut self) -> Result<(), ProtoError> {
        let keys = self
            .periods
            .iter()
            .map(|p| (vetter_label(p), self.issuer.hvk(p)))
            .collect();
        self.verifier.set_live_periods(keys)
    }

    // --- vetters ----------------------------------------------------------------------------

    pub fn grant(&mut self, member: &str) {
        self.grants.insert(member.to_string());
    }

    /// Removal: no credential under any later period. What they hold stays valid until its
    /// period leaves the window, or until [`Self::drop_period`].
    pub fn revoke(&mut self, member: &str) {
        self.grants.remove(member);
    }

    /// Root admission under the CURRENT period, behind the grant check (§3, §13 C3): one
    /// identifier per member and period. `request` is the member's credential request with no
    /// attestations; the issuer rebuilds its session for `member`, so a request replayed by
    /// another member fails. Asking again with the identifier already issued to is a client that
    /// lost the answer, and is re-issued, as `vtc-service` does (a second credential on one key
    /// makes the same tags, so it adds no vetter).
    ///
    /// # Errors
    /// [`ProtoError::NotAVetter`], [`ProtoError::AlreadyIssued`] for another identifier in the
    /// period, or [`ProtoError::Pcs`] if the request does not verify for `member`.
    pub fn issue_vetter_root<R: RngCore + CryptoRng>(
        &mut self,
        member: &str,
        request: &CredentialRequest<Bk>,
        rng: &mut R,
    ) -> Result<PreCredential, ProtoError> {
        if !self.grants.contains(member) {
            return Err(ProtoError::NotAVetter(member.to_string()));
        }
        let period = self.current_period().to_string();
        let key = (member.to_string(), period.clone());
        let id_text = point_text(&request.id)?;
        if self.issued.get(&key).is_some_and(|bound| *bound != id_text) {
            return Err(ProtoError::AlreadyIssued {
                member: member.to_string(),
                label: vetter_label(&period),
            });
        }
        let pre = self.issuer.issue_root(member, &period, request, rng)?;
        self.issued.insert(key, id_text);
        Ok(pre)
    }

    /// Period rotation: a new helper key for the new period, which becomes current; the previous
    /// one stays live; anything older is dropped with its key. Monthly token labels move with it.
    ///
    /// # Errors
    /// [`ProtoError::Pcs`] if a key cannot be checked.
    pub fn rotate(&mut self, new_period: &str) -> Result<(), ProtoError> {
        let previous = self.current_period().to_string();
        self.periods = vec![new_period.to_string(), previous.clone()];
        self.sync_verifier()?;
        let old_labels: Vec<String> = self
            .verifier
            .tokens
            .live_labels()
            .iter()
            .filter(|l| !l.starts_with("token/event/") && **l != monthly_token_label(&previous))
            .cloned()
            .collect();
        for l in old_labels {
            self.verifier.tokens.close_label(&l);
        }
        self.current_token_label = monthly_token_label(new_period);
        let tvk = self.issuer.tvk(&self.current_token_label);
        self.verifier
            .tokens
            .open_label(&self.current_token_label.clone(), tvk);
        Ok(())
    }

    /// Emergency: a period is dropped now, with its key, e.g. to make a removal immediate.
    /// Every request under it fails from then on.
    ///
    /// # Errors
    /// [`ProtoError::Pcs`] if a key cannot be checked.
    pub fn drop_period(&mut self, period: &str) -> Result<(), ProtoError> {
        let period = period_of(period).to_string();
        self.periods.retain(|p| *p != period);
        self.sync_verifier()
    }

    // --- tokens -----------------------------------------------------------------------------

    /// One tick of the drip for `member` under `label` (monthly or event).
    ///
    /// # Errors
    /// [`ProtoError::NotAVetter`], [`ProtoError::EventRefused`], and those of
    /// [`Issuer::issue_tokens`].
    pub fn drip<R: RngCore + CryptoRng>(
        &mut self,
        member: &str,
        tick: u32,
        label: &str,
        requests: &[TokenRequest],
        rng: &mut R,
    ) -> Result<Vec<PreCredential>, ProtoError> {
        if !self.grants.contains(member) {
            return Err(ProtoError::NotAVetter(member.to_string()));
        }
        if let Some(event) = label.strip_prefix("token/event/")
            && !self.events.get(event).is_some_and(|g| g.contains(member))
        {
            return Err(ProtoError::EventRefused(format!(
                "{member} is not in event {event}"
            )));
        }
        self.issuer.issue_tokens(
            &self.verifier.tokens,
            DripOrder {
                member,
                tick,
                label,
                requests,
                quota: self.quota_for(label),
            },
            rng,
        )
    }

    /// Event mode (§5.1): approved by someone outside the group, for a group of at least
    /// `floor` vetters who all hold live grants.
    ///
    /// # Errors
    /// [`ProtoError::EventRefused`] or [`ProtoError::NotAVetter`].
    pub fn approve_event(
        &mut self,
        event_id: &str,
        members: &[&str],
        approver: &str,
        floor: usize,
    ) -> Result<String, ProtoError> {
        if members.contains(&approver) {
            return Err(ProtoError::EventRefused(
                "a vetter cannot approve their own event mode".into(),
            ));
        }
        let group: HashSet<String> = members.iter().map(|m| (*m).to_string()).collect();
        if group.len() < floor {
            return Err(ProtoError::EventRefused(format!(
                "group of {} is below the floor of {floor}",
                group.len()
            )));
        }
        if let Some(m) = group.iter().find(|m| !self.grants.contains(*m)) {
            return Err(ProtoError::NotAVetter(m.clone()));
        }
        self.events.insert(event_id.to_string(), group);
        let label = event_token_label(event_id);
        let tvk = self.issuer.tvk(&label);
        self.verifier.tokens.open_label(&label, tvk);
        Ok(label)
    }

    /// The event's grace period is over: its tokens die.
    pub fn close_event(&mut self, event_id: &str) {
        self.verifier
            .tokens
            .close_label(&event_token_label(event_id));
        self.events.remove(event_id);
    }

    // --- admission --------------------------------------------------------------------------

    pub fn challenge<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> String {
        let mut b = [0u8; 16];
        rng.fill_bytes(&mut b);
        let c: String = b.iter().map(|x| format!("{x:02x}")).collect();
        self.challenges.insert(c.clone());
        c
    }

    /// Consume the challenge, then verify and count (the verifier does the rest).
    ///
    /// # Errors
    /// [`ProtoError::BadChallenge`], and those of [`Verifier::submit`].
    pub fn submit(&mut self, sub: &Submission, now: DateTime<Utc>) -> Result<Decision, ProtoError> {
        if !self.challenges.remove(&sub.challenge) {
            return Err(ProtoError::BadChallenge);
        }
        self.verifier.submit(sub, now)
    }

    pub fn evaluate(&self, id_text: &str, now: DateTime<Utc>) -> Decision {
        self.verifier.evaluate(id_text, now)
    }

    /// Withdrawal of one statement by its tag, for the applicant `id` of the vetter period
    /// `label`.
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
        self.verifier.withdraw(label, id, tag, proof)
    }
}
