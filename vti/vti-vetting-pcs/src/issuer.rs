//! The community's **minting** half: the signing keys, and the two things they sign.
//!
//! Everything here is what [`crate::verifier::Verifier`] deliberately does not have. It is
//! split out from the bookkeeping on purpose: a vetter may hold one root credential per vetter
//! period and draw at most the published drip each tick, and *those facts belong in a store* —
//! `vtc-service` keeps them in a keyspace, where they survive a restart and cannot be lost by a
//! process that forgot. This type holds keys and signs; it counts nothing.
//!
//! # The keys are derived, not stored
//!
//! [`Issuer::derive`] produces every key from one 32-byte secret, deterministically: one helper
//! key per vetter period ([`crate::scheme`]: a period is a key) and one token key per token
//! label. A service derives them from the master secret it already holds rather than minting
//! secrets that must then be backed up, rotated and leaked separately. Each stream is ChaCha20
//! over a SHA-256 of the info string, the community, the period or label, and the secret, which
//! is specified rather than merely current, so the same secret gives the same keys on any
//! machine and any build.
//!
//! The consequence to hold on to: **the master secret is the vetter class**. Change it and
//! every period's `hvk` changes, every vetter's root credential stops verifying, and every
//! submission already in flight fails. A service must check the derived keys against the ones
//! it published before it issues anything — see `vtc-service`'s `pcs_issue::issuer`.
//!
//! # Root admission
//!
//! A vetter's root credential is an ordinary `pcreds` credential request with no attestations,
//! admitted with the decision `d = root` behind the community's grant check. Its `ssid` is
//! [`enrolment_ssid`] of the community, the member and the period, which the community rebuilds
//! for the member that submits rather than taking it from the request: a root request captured
//! and replayed by another member fails `π_iss` (and so cannot lock its owner out of the period).
//! The helper's policy `Pol_k` has a `k` no request reaches, so the policy path never issues:
//! every credential under a period's key is a root admission, and an applicant's request is only
//! ever evaluated (design §13 C4).

use std::sync::Mutex;

use predicate_credential_system::pcreds::{
    Backend, CredentialRequest, Decision, Helper, Policy, Reply,
};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use crate::{
    ProtoError,
    scheme::{Bk, G1, Hvk, Pcreds, Tvk, enc, enrolment_ssid, keys_text, pcreds, period_of, point_text},
    token::{TokenIssuer, TokenRequest, TokenVerifier},
};

/// Domain separator for [`Issuer::derive`]. A change here is a key rotation for every
/// deployment that derives, so it is versioned (v2: one key per period, on `pcreds`).
pub const KEY_DERIVATION_INFO: &[u8] = b"vtc-vetting-pcs-keys/v2\0";

/// The pre-credential a root admission answers with: the vetter unblinds it.
pub type PreCredential = <Bk as Backend>::PreCredential;

/// One tick of the drip, as the community is asked to serve it.
///
/// Grouped rather than passed loose because they travel together and mean nothing apart: the
/// quota that applies is a fact about the label, and the tick is what makes "once" checkable.
pub struct DripOrder<'a> {
    pub member: &'a str,
    pub tick: u32,
    pub label: &'a str,
    pub requests: &'a [TokenRequest],
    /// The published rate for this label — the ordinary drip, or an event's own.
    pub quota: usize,
}

/// The signing half of a community's hidden-vetting deployment.
///
/// One per community. Cheap to rebuild — a key is derived on use, never stored — so a service
/// may hold one for its lifetime or build one per request; both are correct.
pub struct Issuer {
    community: String,
    pcreds: Pcreds,
    seed: [u8; 32],
    /// The token signing keys, behind their own lock: two kinds of signing key, two locks
    /// (§13 C3). The `served` set inside is a *second* guard on the once-a-tick rule, under the
    /// first one the caller keeps in its store.
    tokens: Mutex<TokenIssuer>,
    /// Root admissions are signed one at a time.
    hsk_lock: Mutex<()>,
}

impl std::fmt::Debug for Issuer {
    /// Never the keys: a `{:?}` in a log line is how a signing key reaches a log file.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issuer")
            .field("community", &self.community)
            .finish_non_exhaustive()
    }
}

impl Issuer {
    /// Every key from one secret, deterministically. See the module docs for what that binds
    /// together.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Pcs`] if the deployment parameters cannot be derived for `community`.
    pub fn derive(community: &str, secret: &[u8; 32]) -> Result<Self, ProtoError> {
        // The community is part of the seed, length-framed, so that two communities derived from
        // one master secret never share a key.
        let mut h = Sha256::new();
        h.update(KEY_DERIVATION_INFO);
        h.update((community.len() as u64).to_le_bytes());
        h.update(community.as_bytes());
        h.update(secret);
        Self::from_seed(community, h.finalize().into())
    }

    /// Fresh keys from `rng`. The in-process community object and the tests use this; a service
    /// uses [`Self::derive`], so that a restart finds the same keys.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Pcs`] if the deployment parameters cannot be derived for `community`.
    pub fn generate<R: RngCore + CryptoRng>(
        community: &str,
        rng: &mut R,
    ) -> Result<Self, ProtoError> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(community, seed)
    }

    fn from_seed(community: &str, seed: [u8; 32]) -> Result<Self, ProtoError> {
        Ok(Self {
            community: community.to_string(),
            pcreds: pcreds(community)?,
            seed,
            tokens: Mutex::new(TokenIssuer::new(community, seed)),
            hsk_lock: Mutex::new(()),
        })
    }

    pub fn community(&self) -> &str {
        &self.community
    }
    pub fn pcreds(&self) -> &Pcreds {
        &self.pcreds
    }

    /// The helper of `period` (a bare period such as `2026-09`, or its label `vetter/2026-09`):
    /// its key pair, derived, with an empty issuance record — the community keeps the durable
    /// record of who was issued to, and decides re-issues itself.
    ///
    /// # Panics
    /// Never: `Policy::threshold` refuses only `k = 0`.
    pub fn helper(&self, period: &str) -> Helper<Bk> {
        let period = period_of(period);
        let mut h = Sha256::new();
        h.update(b"vetter-period\0");
        h.update((period.len() as u64).to_le_bytes());
        h.update(period.as_bytes());
        h.update(self.seed);
        let mut rng = ChaCha20Rng::from_seed(h.finalize().into());
        let policy = Policy::threshold(usize::MAX).expect("a nonzero threshold");
        self.pcreds.helper_keygen(policy, &mut rng)
    }

    /// The helper verification key of `period`.
    pub fn hvk(&self, period: &str) -> Hvk {
        self.helper(period).key().vk().clone()
    }

    /// The token verification key of `label`.
    pub fn tvk(&self, label: &str) -> Tvk {
        self.tokens.lock().expect("token signing lock").tvk(label)
    }

    /// The public keys as a community publishes them, multibase: the helper keys of `periods`
    /// and the token keys of `token_labels`, each in the order given ([`crate::scheme`],
    /// "Published keys on the wire").
    ///
    /// # Errors
    ///
    /// [`ProtoError::Pcs`] if a key cannot be encoded.
    pub fn public_text(
        &self,
        periods: &[String],
        token_labels: &[String],
    ) -> Result<(String, String), ProtoError> {
        let hvks: Vec<Hvk> = periods.iter().map(|p| self.hvk(p)).collect();
        let tvks: Vec<Tvk> = token_labels.iter().map(|l| self.tvk(l)).collect();
        Ok((keys_text(&hvks)?, keys_text(&tvks)?))
    }

    /// Admit one vetter as a root user under `period`.
    ///
    /// This is the blind half: the request carries a commitment, and what comes back is a
    /// pre-credential the vetter unblinds. The issuer never sees the credential it made, which
    /// is why it cannot recognise the holder later.
    ///
    /// **It checks nothing about the member** beyond the request being theirs (the `ssid` is
    /// rebuilt for `member`). Whether they hold the role, whether they already have a credential
    /// under this period, and whether the identifier is the one they enrolled with are facts
    /// about a community's records, not about this key: the caller checks them, durably, before
    /// calling.
    ///
    /// `rng` is the issuance randomness. A service passes `OsRng`; a test passes a seeded one.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Pcs`] if the request does not verify for `member` under `period`.
    pub fn issue_root<R: RngCore + CryptoRng>(
        &self,
        member: &str,
        period: &str,
        request: &CredentialRequest<Bk>,
        rng: &mut R,
    ) -> Result<PreCredential, ProtoError> {
        let period = period_of(period);
        let ssid = enrolment_ssid(&self.community, member, period);
        let mut helper = self.helper(period);
        let evaluated = self.pcreds.evaluate_request(&helper, request, &ssid)?;
        let _guard = self.hsk_lock.lock().expect("helper signing lock");
        match self
            .pcreds
            .respond(&mut helper, evaluated, Decision::Root, rng)?
        {
            Reply::PreCredential(pre) => Ok(pre),
            // The record is fresh on every call, so neither occurs for a root admission.
            Reply::Issued | Reply::Fail => Err(ProtoError::AlreadyIssued {
                member: member.to_string(),
                label: crate::scheme::vetter_label(period),
            }),
        }
    }

    /// Blind-sign one tick of the drip: at most `quota` tokens for `member` under `label`.
    ///
    /// `quota` is the community's published drip rate. It is enforced **here**, not by how many
    /// requests a vetter chooses to send: an unchecked batch is an unbounded one, and the whole
    /// point of a token is that it is scarce. The caller has already checked, durably, that
    /// this member holds the role and has not been served for this tick.
    ///
    /// # Errors
    ///
    /// - [`ProtoError::OverQuota`] if more than `quota` tokens were asked for.
    /// - [`ProtoError::LabelNotLive`] if `label` is not open under this issuer's key.
    /// - [`ProtoError::BadOpeningProof`] if a request's opening proof does not verify.
    pub fn issue_tokens<R: RngCore + CryptoRng>(
        &self,
        verifier: &TokenVerifier,
        order: DripOrder<'_>,
        rng: &mut R,
    ) -> Result<Vec<PreCredential>, ProtoError> {
        if order.requests.len() > order.quota {
            return Err(ProtoError::OverQuota {
                asked: order.requests.len(),
                quota: order.quota,
            });
        }
        let mut tokens = self.tokens.lock().expect("token signing lock");
        tokens.issue(
            verifier,
            order.member,
            order.tick,
            order.label,
            order.requests,
            rng,
        )
    }
}

// -------------------------------------------------------------------------------------------
// What crosses the boundary
// -------------------------------------------------------------------------------------------
//
// Enrolment and the drip are exchanges: a vetter asks, the community answers. The bodies are
// here rather than in a transport, because they are the same whichever transport carries them —
// a Trust Task today, a REST call in a test, a direct call in the reference run.
//
// Binary values travel as multibase base58btc over the crate's canonical encoding, the
// convention `wire` already uses.

/// A root request (a `pcreds` credential request with no attestations) in the object form the
/// `pcs-root` and voter `register` schemas give it: `{ "proof": "z…" }`, the multibase of the
/// request's canonical encoding in the one member those schemas require (they leave the suite's
/// members to the suite).
///
/// # Errors
/// [`ProtoError::Pcs`] if the request cannot be encoded.
pub fn request_value(request: &CredentialRequest<Bk>) -> Result<serde_json::Value, ProtoError> {
    Ok(serde_json::json!({ "proof": enc(request)? }))
}

/// The inverse of [`request_value`].
///
/// # Errors
/// [`ProtoError::Serialization`] if `value` has no `proof` string, [`ProtoError::Pcs`] if it does
/// not decode.
pub fn request_from_value(value: &serde_json::Value) -> Result<CredentialRequest<Bk>, ProtoError> {
    let text = value
        .get("proof")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ProtoError::Serialization("the root request has no `proof`".into()))?;
    crate::scheme::dec(text)
}

/// A vetter's request for a root credential under a vetter label.
///
/// `request` is the `pcreds` credential request with no attestations, under the session
/// [`enrolment_ssid`]: a commitment to the vetter's key and a proof that `id` is that key's
/// identifier under the period's helper key. `id` is repeated beside it so the community can
/// read and record it without decoding the request; [`Self::parse`] refuses the two disagreeing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RootRequestWire {
    /// `vetter/<period>` — the label asked for, so a stale client's request is refused rather
    /// than silently served under the current one.
    pub label: String,
    pub id: String,
    /// The `CredentialRequest` ([`request_value`]).
    pub request: serde_json::Value,
}

impl RootRequestWire {
    /// The wire form of `request`.
    ///
    /// # Errors
    /// [`ProtoError::Pcs`] if a value cannot be encoded.
    pub fn of(label: &str, request: &CredentialRequest<Bk>) -> Result<Self, ProtoError> {
        Ok(Self {
            label: label.to_string(),
            id: point_text(&request.id)?,
            request: request_value(request)?,
        })
    }

    /// The identifier and the request, checked to agree.
    ///
    /// # Errors
    /// [`ProtoError::Serialization`] if the request does not decode or names another identifier.
    pub fn parse(&self) -> Result<(G1, CredentialRequest<Bk>), ProtoError> {
        let request = request_from_value(&self.request)?;
        if point_text(&request.id)? != self.id {
            return Err(ProtoError::Serialization(
                "the root request is for another identifier than `id`".into(),
            ));
        }
        Ok((request.id, request))
    }
}

/// The community's answer: the blind pre-credential, which the vetter unblinds into a
/// credential the community has never seen.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RootCredentialWire {
    pub label: String,
    pub pre_credential: String,
}

/// One committed serial with its opening proof, on the wire.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TokenRequestWire {
    pub commitment: String,
    pub opening_proof: String,
}

impl TokenRequestWire {
    /// # Errors
    /// [`ProtoError::Serialization`] if a value cannot be encoded.
    pub fn of(request: &TokenRequest) -> Result<Self, ProtoError> {
        Ok(Self {
            commitment: crate::scheme::enc(&request.commitment)?,
            opening_proof: crate::scheme::enc(&request.opening_proof)?,
        })
    }

    /// # Errors
    /// [`ProtoError::Serialization`] if a value cannot be decoded.
    pub fn to_request(&self) -> Result<TokenRequest, ProtoError> {
        Ok(TokenRequest {
            commitment: crate::scheme::dec(&self.commitment)?,
            opening_proof: crate::scheme::dec(&self.opening_proof)?,
        })
    }
}

/// One tick of the drip, asked for. The tick is the vetter's own schedule counter: it is what
/// makes "once per tick" a rule the community can enforce without knowing whether the vetter
/// has been busy.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TokenBatchRequestWire {
    pub label: String,
    pub tick: u32,
    pub requests: Vec<TokenRequestWire>,
}

/// One tick of the drip, answered.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TokenBatchWire {
    pub label: String,
    pub tick: u32,
    pub pre_credentials: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMUNITY: &str = "did:webvh:QmScid:kernel.example";

    fn periods() -> Vec<String> {
        vec!["2026-10".into(), "2026-09".into()]
    }
    fn labels() -> Vec<String> {
        vec!["token/2026-10".into()]
    }

    /// The property the whole derivation rests on: one secret, the same keys, every time.
    #[test]
    fn derivation_is_deterministic_and_secret_bound() {
        let a = Issuer::derive(COMMUNITY, &[7u8; 32]).unwrap();
        let b = Issuer::derive(COMMUNITY, &[7u8; 32]).unwrap();
        assert_eq!(
            a.public_text(&periods(), &labels()).unwrap(),
            b.public_text(&periods(), &labels()).unwrap()
        );

        // A different secret is a different community key — the failure mode the service has to
        // detect before it issues anything.
        let c = Issuer::derive(COMMUNITY, &[8u8; 32]).unwrap();
        assert_ne!(
            a.public_text(&periods(), &labels()).unwrap(),
            c.public_text(&periods(), &labels()).unwrap()
        );

        // And so is a different community, under the same secret.
        let d = Issuer::derive("did:webvh:QmOther:other.example", &[7u8; 32]).unwrap();
        assert_ne!(
            a.public_text(&periods(), &labels()).unwrap(),
            d.public_text(&periods(), &labels()).unwrap()
        );
    }

    /// One key per period: the periods are unlinkable keys, and a label and its bare period name
    /// the same one.
    #[test]
    fn each_period_has_its_own_key() {
        let issuer = Issuer::derive(COMMUNITY, &[1u8; 32]).unwrap();
        assert_ne!(issuer.hvk("2026-09"), issuer.hvk("2026-10"));
        assert_eq!(issuer.hvk("2026-09"), issuer.hvk("vetter/2026-09"));
        assert_ne!(issuer.tvk("token/2026-09"), issuer.tvk("token/2026-10"));
    }

    /// A vetter asking for more than the community's drip rate is refused, and the refusal
    /// happens before any signature: the quota is the cap, not the vetter's own restraint.
    #[test]
    fn a_batch_over_the_quota_is_refused_and_one_within_it_is_signed() {
        use crate::token::TokenWallet;
        use rand::{SeedableRng, rngs::StdRng};

        const LABEL: &str = "token/2026-09";
        let issuer = Issuer::derive(COMMUNITY, &[2u8; 32]).unwrap();
        let tvk = issuer.tvk(LABEL);
        let verifier = TokenVerifier::new([(LABEL.to_string(), tvk.clone())]);
        let mut rng = StdRng::seed_from_u64(9);
        let mut wallet = TokenWallet::new();

        let greedy = wallet
            .prepare(&tvk, LABEL, "member-1", 1, 8, &mut rng)
            .unwrap();
        assert_eq!(
            issuer
                .issue_tokens(
                    &verifier,
                    DripOrder {
                        member: "member-1",
                        tick: 1,
                        label: LABEL,
                        requests: &greedy,
                        quota: 3,
                    },
                    &mut rng
                )
                .unwrap_err(),
            ProtoError::OverQuota { asked: 8, quota: 3 }
        );

        let within = wallet
            .prepare(&tvk, LABEL, "member-1", 2, 3, &mut rng)
            .unwrap();
        let pres = issuer
            .issue_tokens(
                &verifier,
                DripOrder {
                    member: "member-1",
                    tick: 2,
                    label: LABEL,
                    requests: &within,
                    quota: 3,
                },
                &mut rng,
            )
            .expect("three is within the drip rate");
        assert_eq!(pres.len(), 3);
        wallet
            .receive(&tvk, LABEL, 2, &pres)
            .expect("the tokens unblind under the published key");
        assert_eq!(wallet.free(), 3);
    }
}
