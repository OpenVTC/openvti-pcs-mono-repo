//! Attestation tokens (design §5.1, with §13 C3 and C5): Pointcheval–Sanders blind signatures
//! on secret serials, made with the credential base `Σ-PS` of `pcreds`. No RSA, no new
//! dependency.
//!
//! - One token key `(tvk, tsk)` per live LABEL (`token/<period>`, `token/event/<id>`), never a
//!   helper key: a `Σ-PS` signature on `s` under a period's helper key would be a credential of
//!   that period on the "`usk`" `s`, which the vetter knows. `Σ-PS` signs one scalar, the
//!   serial, so the label is in the key and not in the message, as with the per-month token keys
//!   of design §5.1. Closing a label forgets its key.
//! - Drip: the vetter commits to fresh serials `C_i = g_1^{ρ_i} Y^{s_i}` (the `PrepareIssue` of
//!   `Σ-PS`) with a proof of knowledge of each opening; the community blind-signs them one at a
//!   time under the label's key (C3), at most once per member, label and tick.
//! - Spend: the serial is revealed with a RE-RANDOMISED signature `(σ_1^r, σ_2^r)`; the
//!   community checks it under the key of a live label and records the serial in that label's
//!   spent set. For a uniform `r ≠ 0`, `σ_1^r` is uniform in `G_1 \ {1}` and fixes `σ_2^r`, so
//!   the spend is independent of the blind signing that made the token.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::Mutex,
};

use ark_ec::PrimeGroup;
use ark_ff::{UniformRand, Zero};
use predicate_credential_system::{
    Error as PcsError,
    pcreds::pairing::{Base as PairingBase, G1Request, PSPair, PSSigningKey},
    serialization::to_bytes,
    sigma::{FSProof, GroupRelation, LinearEquation, fiat_shamir},
};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ProtoError,
    scheme::{Base, E, Fr, G1, Tvk, dec, enc, scalar_text},
};

/// One committed serial with its proof of opening.
#[derive(Debug, Clone)]
pub struct TokenRequest {
    pub commitment: G1,
    pub opening_proof: FSProof<Fr>,
}

/// A spent token as the applicant forwards it: the revealed serial and a re-randomised
/// signature.
#[derive(Debug, Clone)]
pub struct TokenSpend {
    pub label: String,
    pub serial: Fr,
    pub shown: PSPair<E>,
}

/// What the spent set said about a spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendOutcome {
    /// First time this serial was seen.
    Fresh,
    /// Seen before with the same `(id, tag)`: a resubmission after `requestMore`.
    AlreadyCounted,
    /// Seen before with another `(id, tag)`. Recorded as an anomaly; the community cannot name
    /// who.
    DoubleSpend,
}

/// The statement `C = g_1^ρ Y^s` over the variables `(s, ρ)`, in that order.
fn opening_relation(tvk: &Tvk, c: &G1) -> Result<GroupRelation<G1>, ProtoError> {
    let mut rel = GroupRelation::new();
    let s = rel.alloc_scalar();
    let rho = rel.alloc_scalar();
    rel.add_equation(LinearEquation::new(
        vec![(rho, G1::generator()), (s, tvk.y1)],
        *c,
    ))?;
    Ok(rel)
}

/// The context of an opening proof: the key, the label, who asks, for which tick, which slot.
/// A proof made for one request cannot be replayed into another.
fn opening_context(
    tvk: &Tvk,
    label: &str,
    member: &str,
    tick: u32,
    index: usize,
    c: &G1,
) -> Result<Vec<u8>, ProtoError> {
    let mut ctx = b"openvtc/hidden-vetting/token-open/0.2\0".to_vec();
    for part in [
        to_bytes(tvk)?,
        label.as_bytes().to_vec(),
        member.as_bytes().to_vec(),
        tick.to_le_bytes().to_vec(),
        (index as u64).to_le_bytes().to_vec(),
        to_bytes(c)?,
    ] {
        ctx.extend((part.len() as u64).to_le_bytes());
        ctx.extend(part);
    }
    Ok(ctx)
}

/// A uniform nonzero scalar.
fn nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Fr {
    loop {
        let r = Fr::rand(rng);
        if !r.is_zero() {
            return r;
        }
    }
}

/// `Verify(tvk, s, σ')`, under the key of the spend's label.
pub fn verify_spend(tvk: &Tvk, spend: &TokenSpend) -> bool {
    <Base as PairingBase<E>>::verify(&(), tvk, &spend.serial, &spend.shown)
}

// -------------------------------------------------------------------------------------------
// Community side
// -------------------------------------------------------------------------------------------

/// Where spent serials are remembered. A serial that un-spends is a double spend, so the
/// community backs this with durable storage; the in-memory default is for tests and for a
/// client that is predicting a verdict.
pub trait SpentLedger: std::any::Any + Send {
    /// Record `(label, serial)` as spent by `(id, tag)`, and say what was there before.
    fn record(
        &mut self,
        label: &str,
        serial: &str,
        id: &str,
        tag: &str,
    ) -> Result<SpendOutcome, ProtoError>;

    /// Forget everything under `label`: its tokens can no longer be spent, so nothing under it
    /// needs remembering.
    fn forget_label(&mut self, label: &str);

    /// For [`TokenVerifier::take_ledger`]; the blanket implementation below is the only one.
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any>;
}

/// The default: one process, no durability.
#[derive(Default)]
pub struct MemoryLedger {
    /// label → serial → (id, tag)
    spent: HashMap<String, HashMap<String, (String, String)>>,
}

impl SpentLedger for MemoryLedger {
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }

    fn record(
        &mut self,
        label: &str,
        serial: &str,
        id: &str,
        tag: &str,
    ) -> Result<SpendOutcome, ProtoError> {
        let set = self.spent.entry(label.to_string()).or_default();
        match set.get(serial) {
            None => {
                set.insert(serial.to_string(), (id.to_string(), tag.to_string()));
                Ok(SpendOutcome::Fresh)
            }
            Some((i, t)) if i == id && t == tag => Ok(SpendOutcome::AlreadyCounted),
            Some(_) => Ok(SpendOutcome::DoubleSpend),
        }
    }

    fn forget_label(&mut self, label: &str) {
        self.spent.remove(label);
    }
}

/// What a VERIFIER needs about tokens: the public key of each live label, and the spent set.
/// The community service holds one of these; so does anything that re-checks a submission from
/// public data alone.
pub struct TokenVerifier {
    keys: BTreeMap<String, Tvk>,
    live: BTreeSet<String>,
    spent: Box<dyn SpentLedger>,
    pub anomalies: Vec<String>,
}

impl TokenVerifier {
    /// From public data only: the key of each live label.
    pub fn new(keys: impl IntoIterator<Item = (String, Tvk)>) -> Self {
        let keys: BTreeMap<String, Tvk> = keys.into_iter().collect();
        Self {
            live: keys.keys().cloned().collect(),
            keys,
            spent: Box::new(MemoryLedger::default()),
            anomalies: Vec::new(),
        }
    }

    /// Swap in a durable ledger (the community service does this at startup).
    #[must_use]
    pub fn with_ledger(mut self, ledger: Box<dyn SpentLedger>) -> Self {
        self.spent = ledger;
        self
    }

    /// Put a ledger in for one call.
    pub fn set_ledger(&mut self, ledger: Box<dyn SpentLedger>) {
        self.spent = ledger;
    }

    /// Take the ledger back out, leaving an empty in-memory one. A caller that has to write
    /// what was spent to storage gets it this way, and downcasts to its own type.
    pub fn take_ledger(&mut self) -> Box<dyn std::any::Any> {
        std::mem::replace(&mut self.spent, Box::new(MemoryLedger::default())).into_any()
    }

    /// The key of a live label, as the manifest publishes it.
    pub fn tvk(&self, label: &str) -> Option<&Tvk> {
        self.keys.get(label)
    }

    pub fn live_labels(&self) -> &BTreeSet<String> {
        &self.live
    }

    /// Open `label` under `tvk`. A label that is live already keeps its key.
    pub fn open_label(&mut self, label: &str, tvk: Tvk) {
        self.keys.entry(label.to_string()).or_insert(tvk);
        self.live.insert(label.to_string());
    }

    /// Closing a label expires its tokens and drops its spent set: nothing under it can be
    /// spent any more, so nothing needs remembering.
    pub fn close_label(&mut self, label: &str) {
        self.keys.remove(label);
        self.live.remove(label);
        self.spent.forget_label(label);
    }

    /// The signature check alone: valid under the key of a live label. Also what the
    /// applicant's engine runs on receipt (§13 C5), with the published keys.
    pub fn signature_ok(&self, spend: &TokenSpend) -> Result<bool, ProtoError> {
        Ok(self.tvk(&spend.label).is_some_and(|tvk| verify_spend(tvk, spend)))
    }

    /// Record a verified spend in its label's spent set.
    pub fn record_spend(
        &mut self,
        spend: &TokenSpend,
        id: &str,
        tag: &str,
    ) -> Result<SpendOutcome, ProtoError> {
        let serial = scalar_text(&spend.serial)?;
        let outcome = self.spent.record(&spend.label, &serial, id, tag)?;
        if outcome == SpendOutcome::DoubleSpend {
            self.anomalies.push(format!(
                "serial {serial} under {} presented twice",
                spend.label
            ));
        }
        Ok(outcome)
    }
}

/// Domain separator for the derivation of a label's token key. Versioned: a change is a key
/// rotation for every label of every deployment that derives.
const TOKEN_KEY_INFO: &[u8] = b"vtc-vetting-pcs-token-key/v2\0";

/// The signing half: only the community that mints tokens has one. Each label's key is derived
/// from the community's secret and the label, so a restart finds the same key and the key never
/// has to be stored. It takes the [`TokenVerifier`] as an argument rather than owning it, so that
/// one spent set and one set of live labels serve both minting and verification.
pub struct TokenIssuer {
    community: String,
    seed: [u8; 32],
    /// One lock per signing key would be finer; one for the issuer keeps blind signing
    /// sequential (§13 C3) and costs nothing at a drip's rate.
    sign_lock: Mutex<()>,
    served: HashSet<(String, String, u32)>,
}

impl std::fmt::Debug for TokenIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenIssuer")
            .field("community", &self.community)
            .finish_non_exhaustive()
    }
}

impl TokenIssuer {
    /// The issuer of `community`, from a 32-byte secret.
    pub fn new(community: &str, seed: [u8; 32]) -> Self {
        Self {
            community: community.to_string(),
            seed,
            sign_lock: Mutex::new(()),
            served: HashSet::new(),
        }
    }

    /// `label`'s key pair, derived.
    fn key_pair(&self, label: &str) -> (Tvk, PSSigningKey<E>) {
        let mut h = Sha256::new();
        h.update(TOKEN_KEY_INFO);
        for part in [self.community.as_bytes(), label.as_bytes()] {
            h.update((part.len() as u64).to_le_bytes());
            h.update(part);
        }
        h.update(self.seed);
        let mut rng = ChaCha20Rng::from_seed(h.finalize().into());
        <Base as PairingBase<E>>::keygen(&(), &mut rng)
    }

    /// The verification key of `label`, as the community publishes it.
    pub fn tvk(&self, label: &str) -> Tvk {
        self.key_pair(label).0
    }

    /// Blind-sign one tick's drip for `member` under `label`. The caller has checked that
    /// `member` holds a live grant (and, for an event label, belongs to the event group).
    ///
    /// # Errors
    /// - [`ProtoError::LabelNotLive`] if `label` is not open, or is open under another key.
    /// - [`ProtoError::AlreadyServedThisTick`] on a second ask for the same tick.
    /// - [`ProtoError::BadOpeningProof`] if a request's opening proof does not verify.
    pub fn issue<R: RngCore + CryptoRng>(
        &mut self,
        verifier: &TokenVerifier,
        member: &str,
        tick: u32,
        label: &str,
        requests: &[TokenRequest],
        rng: &mut R,
    ) -> Result<Vec<PSPair<E>>, ProtoError> {
        let (tvk, tsk) = self.key_pair(label);
        if verifier.tvk(label) != Some(&tvk) {
            return Err(ProtoError::LabelNotLive(label.to_string()));
        }
        let served = (member.to_string(), label.to_string(), tick);
        if self.served.contains(&served) {
            return Err(ProtoError::AlreadyServedThisTick {
                member: member.to_string(),
                tick,
            });
        }
        for (i, req) in requests.iter().enumerate() {
            let rel = opening_relation(&tvk, &req.commitment)?;
            let ctx = opening_context(&tvk, label, member, tick, i, &req.commitment)?;
            if !fiat_shamir::verify(&rel, &ctx, &req.opening_proof) {
                return Err(ProtoError::BadOpeningProof(i));
            }
        }
        let pres = {
            let _guard = self.sign_lock.lock().expect("token signing lock");
            requests
                .iter()
                .map(|req| {
                    <Base as PairingBase<E>>::blind_issue(&(), &tsk, &G1Request(req.commitment), rng)
                        .ok_or(ProtoError::Pcs(PcsError::InvalidIssuanceEncoding))
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        self.served.insert(served);
        Ok(pres)
    }
}

// -------------------------------------------------------------------------------------------
// Vetter side (inside the vetter's VTA: the PCS engine)
// -------------------------------------------------------------------------------------------

struct Held {
    label: String,
    serial: Fr,
    minted_tick: u32,
    cred: PSPair<E>,
    reserved: bool,
}

struct Pending {
    label: String,
    tick: u32,
    serial: Fr,
    rho: Fr,
}

/// One blinded serial asked for and not yet answered, as storage keeps it.
///
/// **SECRET.** The serial and its blinding factor are what unblind the community's answer into
/// a token; a copy of them is a copy of the token the answer will make. They belong exactly
/// where [`HeldToken`] belongs.
///
/// Kept per `(label, tick)` because a vetter can have several draws in flight at once — a
/// catch-up after time away, or the ordinary label beside an event's — and an answer has to
/// find the serials of its own request and no other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingToken {
    pub label: String,
    pub tick: u32,
    /// SECRET.
    pub serial: String,
    /// SECRET.
    pub rho: String,
}

/// One token the vetter holds, unspent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HeldToken {
    pub label: String,
    /// SECRET until spent: the serial is what the community records.
    pub serial: String,
    pub minted_tick: u32,
    pub credential: String,
}

impl HeldToken {
    pub fn of(
        label: &str,
        serial: &Fr,
        minted_tick: u32,
        cred: &PSPair<E>,
    ) -> Result<Self, ProtoError> {
        Ok(Self {
            label: label.to_string(),
            serial: enc(serial)?,
            minted_tick,
            credential: enc(cred)?,
        })
    }

    pub fn parts(&self) -> Result<(Fr, PSPair<E>), ProtoError> {
        Ok((dec::<Fr>(&self.serial)?, dec::<PSPair<E>>(&self.credential)?))
    }
}

/// The vetter's bucket.
#[derive(Default)]
pub struct TokenWallet {
    held: Vec<Held>,
    pending: Vec<Pending>,
}

/// A token set aside when a request is accepted (§5.2), identified by its serial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    pub label: String,
    pub serial: Fr,
}

impl TokenWallet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Draw `r` serials for one tick and commit to them under the label's key `tvk`.
    ///
    /// Replaces whatever was in flight for the same `(label, tick)` — asking again is a new
    /// request, and the old one's answer would not unblind under these serials — and leaves every
    /// other draw in flight alone.
    pub fn prepare<R: RngCore + CryptoRng>(
        &mut self,
        tvk: &Tvk,
        label: &str,
        member: &str,
        tick: u32,
        r: usize,
        rng: &mut R,
    ) -> Result<Vec<TokenRequest>, ProtoError> {
        self.forget(label, tick);
        let mut out = Vec::with_capacity(r);
        for i in 0..r {
            let (serial, rho) = (Fr::rand(rng), Fr::rand(rng));
            let c = <Base as PairingBase<E>>::prepare_issue(&(), tvk, &serial, &rho)
                .ok_or(ProtoError::Pcs(PcsError::InvalidIssuanceEncoding))?
                .0;
            let rel = opening_relation(tvk, &c)?;
            let ctx = opening_context(tvk, label, member, tick, i, &c)?;
            let opening_proof = fiat_shamir::prove(&rel, &[serial, rho], &ctx, rng)?;
            out.push(TokenRequest {
                commitment: c,
                opening_proof,
            });
            self.pending.push(Pending {
                label: label.to_string(),
                tick,
                serial,
                rho,
            });
        }
        Ok(out)
    }

    /// Unblind the answers to the draw for `(label, tick)` and keep them, failing closed on any
    /// that does not verify.
    ///
    /// The draw's serials are consumed whatever the outcome: an answer that does not unblind
    /// will not unblind on a second try either.
    pub fn receive(
        &mut self,
        tvk: &Tvk,
        label: &str,
        tick: u32,
        pres: &[PSPair<E>],
    ) -> Result<(), ProtoError> {
        let (pending, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending)
            .into_iter()
            .partition(|p| p.label == label && p.tick == tick);
        self.pending = rest;
        if pending.len() != pres.len() {
            return Err(ProtoError::CountMismatch {
                statements: pending.len(),
                attestations: pres.len(),
            });
        }
        for (p, pre) in pending.into_iter().zip(pres) {
            let cred = <Base as PairingBase<E>>::unblind(&(), tvk, &p.serial, pre, &p.rho)
                .ok_or(ProtoError::Pcs(PcsError::InvalidPreCredential))?;
            if !<Base as PairingBase<E>>::verify(&(), tvk, &p.serial, &cred) {
                return Err(ProtoError::Pcs(PcsError::InvalidPreCredential));
            }
            self.held.push(Held {
                label: p.label,
                serial: p.serial,
                minted_tick: p.tick,
                cred,
                reserved: false,
            });
        }
        Ok(())
    }

    /// Tokens whose label is no longer live are gone (the FIFO of §5.1).
    ///
    /// So is any draw still in flight under one: its answer would make a token nobody accepts.
    pub fn expire(&mut self, live: &BTreeSet<String>) {
        self.held.retain(|h| live.contains(&h.label));
        self.pending.retain(|p| live.contains(&p.label));
    }

    /// Drop the draw in flight for `(label, tick)`, if there is one: the community refused it,
    /// or it is being asked again.
    pub fn forget(&mut self, label: &str, tick: u32) {
        self.pending
            .retain(|p| !(p.label == label && p.tick == tick));
    }

    /// The draws in flight, as `(label, tick)`, in the order they were asked for.
    #[must_use]
    pub fn in_flight(&self) -> Vec<(String, u32)> {
        let mut out: Vec<(String, u32)> = Vec::new();
        for p in &self.pending {
            if !out.iter().any(|(l, t)| *l == p.label && *t == p.tick) {
                out.push((p.label.clone(), p.tick));
            }
        }
        out
    }

    /// The draws in flight, for storage.
    pub fn pending_snapshot(&self) -> Result<Vec<PendingToken>, ProtoError> {
        self.pending
            .iter()
            .map(|p| {
                Ok(PendingToken {
                    label: p.label.clone(),
                    tick: p.tick,
                    serial: enc(&p.serial)?,
                    rho: enc(&p.rho)?,
                })
            })
            .collect()
    }

    /// Put stored draws back in flight, so an answer that arrives after the engine was stored
    /// and restored still unblinds.
    pub fn restore_pending(&mut self, pending: &[PendingToken]) -> Result<(), ProtoError> {
        for p in pending {
            self.pending.push(Pending {
                label: p.label.clone(),
                tick: p.tick,
                serial: dec::<Fr>(&p.serial)?,
                rho: dec::<Fr>(&p.rho)?,
            });
        }
        Ok(())
    }

    /// The unspent tokens, for storage. A reserved token stores as unreserved: a reservation
    /// belongs to a session that did not survive the restart either.
    pub fn snapshot(&self) -> Result<Vec<HeldToken>, ProtoError> {
        self.held
            .iter()
            .map(|h| HeldToken::of(&h.label, &h.serial, h.minted_tick, &h.cred))
            .collect()
    }

    /// Restore a bucket from storage.
    pub fn restore(tokens: &[HeldToken]) -> Result<Self, ProtoError> {
        let mut wallet = Self::new();
        for t in tokens {
            let (serial, cred) = t.parts()?;
            wallet.held.push(Held {
                label: t.label.clone(),
                serial,
                minted_tick: t.minted_tick,
                cred,
                reserved: false,
            });
        }
        Ok(wallet)
    }

    pub fn free(&self) -> usize {
        self.held.iter().filter(|h| !h.reserved).count()
    }

    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// Reserve the NEWEST free token (§5.1 step 3), preferring `prefer_label` when given (an
    /// event label during its event).
    pub fn reserve(&mut self, prefer_label: Option<&str>) -> Option<Reservation> {
        let pick = self
            .held
            .iter_mut()
            .filter(|h| !h.reserved)
            .max_by_key(|h| (prefer_label.is_some_and(|l| l == h.label), h.minted_tick))?;
        pick.reserved = true;
        Some(Reservation {
            label: pick.label.clone(),
            serial: pick.serial,
        })
    }

    pub fn release(&mut self, r: &Reservation) {
        if let Some(h) = self.held.iter_mut().find(|h| h.serial == r.serial) {
            h.reserved = false;
        }
    }

    /// Spend a reservation: the token leaves the wallet as a re-randomised signature.
    pub fn spend<R: RngCore + CryptoRng>(
        &mut self,
        r: &Reservation,
        rng: &mut R,
    ) -> Result<TokenSpend, ProtoError> {
        let pos = self
            .held
            .iter()
            .position(|h| h.serial == r.serial && h.reserved)
            .ok_or(ProtoError::AtCapacity { available_from: 0 })?;
        let h = self.held.remove(pos);
        let k = nonzero_scalar(rng);
        Ok(TokenSpend {
            label: h.label,
            serial: h.serial,
            shown: PSPair {
                s1: h.cred.s1 * k,
                s2: h.cred.s2 * k,
            },
        })
    }
}
