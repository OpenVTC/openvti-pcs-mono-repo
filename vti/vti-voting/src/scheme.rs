//! The scheme instance and the labels, on `pcreds` (the paper's `Π_PCreds`).
//!
//! - The instance is hidden vetting's (BLS12-381, Σ-PS, `Tag_DDH`), reused by alias.
//! - The **deployment label is voting's own**, `<community>#voting-pcs`: its `pp`, its helper
//!   keys and so every ticket are separate from the community's vetting keys. A vetting credential
//!   can never stand for a ticket.
//! - **One helper key per election.** `pcreds` has no class labels — a credential certifies `usk`
//!   alone — so the election is in the KEY: a ticket is a root credential under its election's
//!   helper key, good for exactly that election, and the electoral roll is whoever was issued
//!   under it. The election's key is the `votingKey` of its parameters, so a [`VotingParams`] is
//!   the public half of ONE election.
//! - A cast is a `pcreds` attestation (`R_att`) at the election's point `x_E`
//!   ([`VotingParams::cast_point`]): `t = Tag(usk, x_E)` is fixed by the voter's key and the
//!   election, so it is the cast's nullifier, and under DDH it is unlinkable to the voter's
//!   identifier `Tag(usk, x_0)`, which the registrar saw.

use predicate_credential_system::pcreds::Policy;

pub use vti_vetting_pcs::scheme::{
    Base, Bk, CheckedHvk, E, Fr, G1, Hvk, Open, Pcreds, Tag, Usk, key_text, point_text,
};

use crate::{
    VotingError,
    election::{Election, frame},
};

pub fn deployment_label(community: &str) -> Vec<u8> {
    format!("{community}#voting-pcs").into_bytes()
}

/// The scheme instance for `community`'s voting deployment.
///
/// # Errors
/// [`VotingError::Pcs`] if the deployment parameters cannot be derived.
pub fn open(community: &str) -> Result<Pcreds, VotingError> {
    Ok(Pcreds::setup(&deployment_label(community))?)
}

/// The registrar's policy: no request ever meets it, so every ticket is a root admission.
pub(crate) fn policy() -> Policy {
    Policy::threshold(usize::MAX).expect("a nonzero threshold")
}

/// The `ssid` of a ticket request: the community and the election. The registrar rebuilds it
/// rather than taking it from the request, so a request made for one election does not verify
/// for another.
pub fn ticket_ssid(election: &Election) -> Vec<u8> {
    let mut ssid = b"vti/vote/ticket/0.2\0".to_vec();
    frame(&mut ssid, election.community().as_bytes());
    frame(&mut ssid, election.id().as_str().as_bytes());
    frame(&mut ssid, election.manifest_digest());
    ssid
}

/// What a voter and a ballot box need of one election of a community: the community, the scheme
/// instance, and the election's published helper key `hvk`. Nothing here is secret.
#[derive(Clone)]
pub struct VotingParams {
    community: String,
    open: Pcreds,
    hvk: CheckedHvk,
}

impl std::fmt::Debug for VotingParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VotingParams")
            .field("community", &self.community)
            .finish_non_exhaustive()
    }
}

impl VotingParams {
    /// From an election's published voting key.
    ///
    /// # Errors
    /// [`VotingError::InvalidCommunity`] for an unusable identifier; [`VotingError::Pcs`] if the
    /// deployment parameters cannot be derived, or `hvk` is not a key of the deployment.
    pub fn new(community: &str, hvk: Hvk) -> Result<Self, VotingError> {
        crate::election::check_community(community)?;
        let open = open(community)?;
        let hvk = open.helper_key(&hvk)?;
        Ok(Self {
            community: community.to_string(),
            open,
            hvk,
        })
    }

    pub fn community(&self) -> &str {
        &self.community
    }
    pub fn open(&self) -> &Pcreds {
        &self.open
    }
    /// The election's checked helper key.
    pub fn hvk(&self) -> &CheckedHvk {
        &self.hvk
    }

    /// `x_E`, the point every cast in `election` attests at: the recipient point
    /// `H_req(⟨pp, hvk, id_E, j⟩)` of the election's public point `id_E` ([`Election::point`]),
    /// which is never the identifier point `x_0` of the key, so a cast's tag is never a voter's
    /// identifier.
    ///
    /// # Errors
    /// [`VotingError::Pcs`] if a point cannot be derived.
    pub fn cast_point(&self, election: &Election) -> Result<Fr, VotingError> {
        Ok(self.open.recipient_point(self.hvk.vk(), &election.point()?)?)
    }
}
