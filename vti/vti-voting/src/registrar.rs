//! The community's half: the voting helper key, and the one thing it signs — tickets.
//!
//! This type holds a key and signs; it counts nothing. Whether the requester is eligible for an
//! election, and whether they already hold a ticket for it, are facts about the community's
//! records: the caller checks them durably, and logs the member-signed request, before calling
//! [`Registrar::issue_ticket`] (VTI-VOT-022 requires that record).
//!
//! # The keys are derived, not stored
//!
//! As hidden vetting's issuer: [`Registrar::derive`] produces the key pair from a 32-byte secret
//! over ChaCha20 seeded with `SHA-256(info ‖ len ‖ community ‖ secret)`. The info string is
//! voting's own, so the same master secret gives a vetting key and a voting key that are
//! unrelated. Change the secret and `hvk` changes: every ticket of an open election stops
//! verifying.

use std::sync::Mutex;

use predicate_credential_system::pcreds::{Backend, Decision, Helper, Reply};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use crate::{
    VotingError,
    election::{Election, check_community},
    scheme::{Bk, G1, Hvk, Pcreds, VotingParams, key_text, open, policy, ticket_ssid},
    voter::TicketRequest,
};

/// v2: one helper key per election, on `pcreds`.
pub const KEY_DERIVATION_INFO: &[u8] = b"vti-voting-pcs-keys/v2\0";

/// What [`Registrar::issue_ticket`] returns: the voter unblinds it into their ticket.
pub type PreTicket = <Bk as Backend>::PreCredential;

pub struct Registrar {
    community: String,
    open: Pcreds,
    seed: [u8; 32],
    /// Issuance is sequential: the scheme's security argument holds for sequential issuance
    /// under one helper key, and the library does not enforce it.
    hsk_lock: Mutex<()>,
}

impl std::fmt::Debug for Registrar {
    /// Never the key: a `{:?}` in a log line is how a signing key reaches a log file.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registrar")
            .field("community", &self.community)
            .finish_non_exhaustive()
    }
}

impl Registrar {
    /// Every election's key from one secret, deterministically.
    ///
    /// # Errors
    /// [`VotingError::InvalidCommunity`] or [`VotingError::Pcs`].
    pub fn derive(community: &str, secret: &[u8; 32]) -> Result<Self, VotingError> {
        check_community(community)?;
        let mut h = Sha256::new();
        h.update(KEY_DERIVATION_INFO);
        h.update((community.len() as u64).to_le_bytes());
        h.update(community.as_bytes());
        h.update(secret);
        Self::from_seed(community, h.finalize().into())
    }

    /// Fresh keys from `rng`. Tests use this; a service uses [`Self::derive`].
    ///
    /// # Errors
    /// [`VotingError::InvalidCommunity`] or [`VotingError::Pcs`].
    pub fn generate<R: RngCore + CryptoRng>(
        community: &str,
        rng: &mut R,
    ) -> Result<Self, VotingError> {
        check_community(community)?;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(community, seed)
    }

    fn from_seed(community: &str, seed: [u8; 32]) -> Result<Self, VotingError> {
        Ok(Self {
            community: community.to_string(),
            open: open(community)?,
            seed,
            hsk_lock: Mutex::new(()),
        })
    }

    pub fn community(&self) -> &str {
        &self.community
    }

    /// `election`'s helper: its key pair, derived from the secret and the election's identity,
    /// with an empty issuance record — the community keeps the durable record of who holds a
    /// ticket.
    fn helper(&self, election: &Election) -> Helper<Bk> {
        let mut h = Sha256::new();
        h.update(b"voter-election\0");
        for part in [
            election.id().as_str().as_bytes(),
            election.manifest_digest().as_slice(),
        ] {
            h.update((part.len() as u64).to_le_bytes());
            h.update(part);
        }
        h.update(self.seed);
        self.open
            .helper_keygen(policy(), &mut ChaCha20Rng::from_seed(h.finalize().into()))
    }

    /// `election`'s helper verification key: its published `votingKey`.
    pub fn hvk(&self, election: &Election) -> Hvk {
        self.helper(election).key().vk().clone()
    }

    /// The public half of `election`, as voters and ballot boxes take it.
    pub fn params(&self, election: &Election) -> VotingParams {
        VotingParams::new(&self.community, self.hvk(election))
            .expect("the community was checked at construction, and the key is the deployment's")
    }

    /// `election`'s `votingKey` as the community publishes it, multibase.
    ///
    /// # Errors
    /// [`VotingError::Serialization`] if the key cannot be encoded.
    pub fn public_text(&self, election: &Election) -> Result<String, VotingError> {
        key_text(&self.hvk(election)).map_err(|e| VotingError::Serialization(e.to_string()))
    }

    /// Sign one voter's blinded request for a ticket to `election`: a root admission under the
    /// election's key, for the identifier `id` the request is for.
    ///
    /// The request carries a commitment; what comes back is a pre-credential only the voter can
    /// unblind. The registrar never sees the ticket it made, which is why it cannot recognise
    /// the ticket's casts later.
    ///
    /// # Errors
    /// - [`VotingError::WrongCommunity`] if `election` is another community's.
    /// - [`VotingError::Pcs`] if the request does not verify for `election`, or is for another
    ///   identifier than `id`.
    pub fn issue_ticket<R: RngCore + CryptoRng>(
        &self,
        election: &Election,
        id: &G1,
        request: &TicketRequest,
        rng: &mut R,
    ) -> Result<PreTicket, VotingError> {
        if election.community() != self.community {
            return Err(VotingError::WrongCommunity {
                expected: self.community.clone(),
                actual: election.community().to_string(),
            });
        }
        if request.id != *id {
            return Err(VotingError::Pcs(
                predicate_credential_system::Error::IdentifierMismatch,
            ));
        }
        let mut helper = self.helper(election);
        let evaluated = self
            .open
            .evaluate_request(&helper, request, &ticket_ssid(election))?;
        let _guard = self.hsk_lock.lock().expect("helper signing lock");
        match self.open.respond(&mut helper, evaluated, Decision::Root, rng)? {
            Reply::PreCredential(pre) => Ok(pre),
            // The record is fresh on every call: neither occurs for a root admission.
            Reply::Issued | Reply::Fail => Err(VotingError::Pcs(
                predicate_credential_system::Error::IdentifierMismatch,
            )),
        }
    }
}
