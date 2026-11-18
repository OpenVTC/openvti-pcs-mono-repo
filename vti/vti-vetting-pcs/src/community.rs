//! A community's PUBLISHED parameters: what a member needs to attest, prove or check, and
//! nothing the community keeps to itself.
//!
//! The applicant and vetter engines work from this rather than from [`crate::vtc::Vtc`],
//! because in a deployment they never hold the community object at all — they hold what the
//! manifest published (`vetting.ext`, design §8). The community's own copy is
//! [`Vtc::params`](crate::vtc::Vtc::params), so the tests drive the same code path a client
//! does.
//!
//! One helper key per live vetter label and one token key per live token label
//! ([`crate::scheme`], "Published keys on the wire").

use std::collections::BTreeMap;

use crate::{
    ProtoError,
    scheme::{CheckedHvk, Hvk, Pcreds, Tvk, keys_from_text, pcreds},
    token::{TokenSpend, TokenVerifier},
};

/// The published half of a community's hidden-vetting deployment.
pub struct CommunityParams {
    community: String,
    pcreds: Pcreds,
    /// Live vetter labels, current first, each with its checked helper key.
    periods: Vec<(String, CheckedHvk)>,
    tokens: TokenVerifier,
    /// How many tokens a vetter may draw per tick. Published because the vetter has to know
    /// what to ask for, and because the community enforces it whatever the vetter asks.
    drip_per_tick: usize,
}

impl CommunityParams {
    /// From what a manifest carries: the two key lists as multibase, and the live labels they
    /// are aligned with.
    ///
    /// # Errors
    /// [`ProtoError::Serialization`] if a key list cannot be decoded or does not match its
    /// labels, [`ProtoError::Pcs`] if a helper key is not a key of this deployment.
    pub fn published(
        community: &str,
        helper_keys: &str,
        token_keys: &str,
        vetter_labels: Vec<String>,
        token_labels: Vec<String>,
        drip_per_tick: usize,
    ) -> Result<Self, ProtoError> {
        let hvks: Vec<Hvk> = keys_from_text(helper_keys)?;
        let tvks: Vec<Tvk> = keys_from_text(token_keys)?;
        Self::new(community, hvks, tvks, vetter_labels, token_labels, drip_per_tick)
    }

    /// From values already decoded: `hvks[i]` is the key of `vetter_labels[i]`, and `tvks[i]`
    /// of `token_labels[i]`.
    ///
    /// # Errors
    /// [`ProtoError::Serialization`] if a list does not match its labels, [`ProtoError::Pcs`]
    /// if the deployment parameters cannot be derived or a helper key is not one of its keys.
    pub fn new(
        community: &str,
        hvks: Vec<Hvk>,
        tvks: Vec<Tvk>,
        vetter_labels: Vec<String>,
        token_labels: Vec<String>,
        drip_per_tick: usize,
    ) -> Result<Self, ProtoError> {
        if hvks.len() != vetter_labels.len() {
            return Err(ProtoError::Serialization(format!(
                "{} helper keys for {} vetter labels",
                hvks.len(),
                vetter_labels.len()
            )));
        }
        if tvks.len() != token_labels.len() {
            return Err(ProtoError::Serialization(format!(
                "{} token keys for {} token labels",
                tvks.len(),
                token_labels.len()
            )));
        }
        let pcreds = pcreds(community)?;
        let periods = vetter_labels
            .into_iter()
            .zip(hvks)
            .map(|(label, vk)| Ok((label, pcreds.helper_key(&vk)?)))
            .collect::<Result<Vec<_>, ProtoError>>()?;
        Ok(Self {
            community: community.to_string(),
            pcreds,
            periods,
            tokens: TokenVerifier::new(token_labels.into_iter().zip(tvks)),
            drip_per_tick,
        })
    }

    pub fn community(&self) -> &str {
        &self.community
    }
    pub fn pcreds(&self) -> &Pcreds {
        &self.pcreds
    }
    /// The scheme instance, by its earlier name.
    pub fn open(&self) -> &Pcreds {
        &self.pcreds
    }
    /// The checked helper key of a live vetter label (`vetter/<period>`).
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
    /// The current vetter label: the first published.
    ///
    /// # Errors
    /// [`ProtoError::PeriodNotLive`] if no label is live.
    pub fn current_label(&self) -> Result<&str, ProtoError> {
        self.periods
            .first()
            .map(|(l, _)| l.as_str())
            .ok_or_else(|| ProtoError::PeriodNotLive("(none)".into()))
    }
    pub fn tokens(&self) -> &TokenVerifier {
        &self.tokens
    }
    /// Live vetter labels, current first.
    pub fn vetter_labels(&self) -> Vec<String> {
        self.periods.iter().map(|(l, _)| l.clone()).collect()
    }
    /// The live vetter labels with their keys, current first.
    pub fn helper_keys(&self) -> BTreeMap<String, Hvk> {
        self.periods
            .iter()
            .map(|(l, k)| (l.clone(), k.vk().clone()))
            .collect()
    }
    /// The published drip rate: what a vetter asks for each tick, and the most the community
    /// will sign.
    pub fn drip_per_tick(&self) -> usize {
        self.drip_per_tick
    }

    /// Whether a token verifies under the published key of a live label.
    ///
    /// # Errors
    /// Never, today; kept fallible for a key that has to be decoded on use.
    pub fn token_ok(&self, spend: &TokenSpend) -> Result<bool, ProtoError> {
        self.tokens.signature_ok(spend)
    }
}
