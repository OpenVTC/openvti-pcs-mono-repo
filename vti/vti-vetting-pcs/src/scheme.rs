//! The instantiation and the labels, on `pcreds` (the paper's `Π_PCreds`).
//!
//! - ONE deployment label per community, with no period in it: `pp` is fixed for the life of
//!   the community.
//! - ONE helper key per vetter period. The class labels `vetter/<period>` of design §13 C1 lived
//!   under one long-lived key, but `pcreds` has no class labels: every identifier and tag is a
//!   function of the helper key (`x_0 = H_id(⟨hvk⟩)`, `x_Q = H_req(⟨pp, hvk, id_Q, j_Q⟩)`). So a
//!   period is a key — the "epoch rotation of `(hvk, hsk)`" of design §4.3. A vetter holds one
//!   credential per period, an applicant registers under one period, and the community evaluates
//!   a request under that period's key alone. The label `vetter/<period>` still names it on the
//!   wire.
//! - Tokens use one key per token label (`token/<period>`, `token/event/<id>`), never a helper
//!   key ([`crate::token`]).
//!
//! # Published keys on the wire
//!
//! The published configuration has one `helperKey` and one `tokenKey` member (the
//! `vetting/_shared/0.1/hidden-vetting` `PublishedConfig`). With a key per period and per
//! label, each member now carries the canonical encoding of the LIST of keys, in the order of
//! `vetterLabels` and `tokenLabels` respectively ([`keys_text`], [`keys_from_text`]). The shape
//! of the configuration is unchanged; the meaning of the two strings is.

use ark_bls12_381::{Bls12_381, G1Projective};
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use predicate_credential_system::{
    hash::bls12_381::G1Hasher,
    kiprf::DDH,
    pcreds::{
        Backend, HelperKey, Protocol, User,
        pairing::{PS, PSVerificationKey, PairingBackend},
    },
    serialization::{from_bytes, from_multibase, to_bytes, to_multibase},
};

use crate::ProtoError;

pub type E = Bls12_381;
pub type G1 = G1Projective;
pub type Fr = ark_bls12_381::Fr;
/// `Tag_DDH` over `G_1`: identifiers and attestation tags.
pub type Tag = DDH<G1, G1Hasher>;
/// `Σ-PS`: the credential base of the main pairing instantiation, which the tokens reuse.
pub type Base = PS;
/// `Σ-PS` with `Tag_DDH` over BLS12-381: the paper's main pairing instantiation.
pub type Bk = PairingBackend<E, Base, Tag>;
/// `Π_PCreds` for [`Bk`], under a community's deployment label.
pub type Pcreds = Protocol<Bk>;
/// The earlier name of the scheme instance, kept so that callers read the same.
pub type Open = Pcreds;
/// A helper verification key (`hvk`) as it travels: one per vetter period.
pub type Hvk = <Bk as Backend>::VerificationKey;
/// A token verification key (`tvk`): one per token label.
pub type Tvk = PSVerificationKey<E>;
/// A member's PCS secret key `usk`.
pub type Usk = <Bk as Backend>::UserKey;
/// A checked helper key, with its identifier point.
pub type CheckedHvk = HelperKey<Bk>;
/// A user registered under one helper key.
pub type Member = User<Bk>;

pub fn deployment_label(community: &str) -> Vec<u8> {
    format!("{community}#vetting-pcs").into_bytes()
}

/// The scheme instance for `community`.
///
/// # Errors
/// [`ProtoError::Pcs`] if the deployment parameters cannot be derived.
pub fn pcreds(community: &str) -> Result<Pcreds, ProtoError> {
    Ok(Pcreds::setup(&deployment_label(community))?)
}

/// The wire label of a vetter period: `vetter/<period>`.
pub fn vetter_label(period: &str) -> String {
    format!("vetter/{period}")
}

/// The period of a vetter label, or the label itself when it has no `vetter/` prefix.
pub fn period_of(label: &str) -> &str {
    label.strip_prefix("vetter/").unwrap_or(label)
}

pub fn monthly_token_label(period: &str) -> String {
    format!("token/{period}")
}

pub fn event_token_label(event_id: &str) -> String {
    format!("token/event/{event_id}")
}

/// The `ssid` of a vetter's root request: the community, the member and the period. The
/// community rebuilds it for the member that submits rather than taking it from the request, so
/// that a root request is bound to that member: one replayed by another member fails `π_iss`.
pub fn enrolment_ssid(community: &str, member: &str, period: &str) -> Vec<u8> {
    let mut ssid = b"openvtc/hidden-vetting/enrol/0.1\0".to_vec();
    for part in [community, member, period] {
        ssid.extend((part.len() as u64).to_le_bytes());
        ssid.extend(part.as_bytes());
    }
    ssid
}

/// Multibase text of a group element (identifiers, tags).
pub fn point_text(p: &G1) -> Result<String, ProtoError> {
    Ok(to_multibase(&to_bytes(p)?))
}

/// Multibase text of any canonically-encodable value.
///
/// # Errors
/// [`ProtoError::Pcs`] if the value cannot be encoded.
pub fn enc<T: CanonicalSerialize>(v: &T) -> Result<String, ProtoError> {
    Ok(to_multibase(&to_bytes(v)?))
}

/// The inverse of [`enc`], with validated decoding.
///
/// # Errors
/// [`ProtoError::Pcs`] if the text is not multibase base58btc, or the bytes are not a valid
/// encoding of `T`.
pub fn dec<T: CanonicalDeserialize>(s: &str) -> Result<T, ProtoError> {
    Ok(from_bytes(&from_multibase(s)?)?)
}

/// Multibase text of one verification key.
///
/// # Errors
/// [`ProtoError::Pcs`] if the key cannot be encoded.
pub fn key_text<T: CanonicalSerialize>(key: &T) -> Result<String, ProtoError> {
    enc(key)
}

/// Multibase text of a list of verification keys, as `helperKey` and `tokenKey` publish them
/// (module docs).
///
/// # Errors
/// [`ProtoError::Pcs`] if a key cannot be encoded.
pub fn keys_text<T: CanonicalSerialize>(keys: &[T]) -> Result<String, ProtoError> {
    let mut out = Vec::new();
    (keys.len() as u64)
        .serialize_compressed(&mut out)
        .map_err(predicate_credential_system::Error::from)?;
    for k in keys {
        k.serialize_compressed(&mut out)
            .map_err(predicate_credential_system::Error::from)?;
    }
    Ok(to_multibase(&out))
}

/// The inverse of [`keys_text`], with validated decoding, refusing trailing bytes.
///
/// # Errors
/// [`ProtoError::Pcs`] or [`ProtoError::Serialization`] if the text does not decode.
pub fn keys_from_text<T: CanonicalDeserialize>(text: &str) -> Result<Vec<T>, ProtoError> {
    let bytes = from_multibase(text)?;
    let mut reader = bytes.as_slice();
    let n = u64::deserialize_compressed(&mut reader)
        .map_err(predicate_credential_system::Error::from)?;
    if n > 1024 {
        return Err(ProtoError::Serialization(format!(
            "{n} keys is not a plausible list"
        )));
    }
    let mut keys = Vec::with_capacity(n as usize);
    for _ in 0..n {
        keys.push(
            T::deserialize_compressed(&mut reader)
                .map_err(predicate_credential_system::Error::from)?,
        );
    }
    if !reader.is_empty() {
        return Err(ProtoError::Serialization(
            "trailing bytes after the key list".into(),
        ));
    }
    Ok(keys)
}

/// Multibase text of a value labelled with the vetter period it belongs to: how an attestation,
/// an attestation request and a credential request travel in the members that carried a bare
/// value before periods were keys (`attestation`, `applicantId`, `proof`).
///
/// # Errors
/// [`ProtoError::Pcs`] if the value cannot be encoded.
pub fn labelled_text<T: CanonicalSerialize>(label: &str, value: &T) -> Result<String, ProtoError> {
    let mut out = Vec::new();
    label
        .as_bytes()
        .to_vec()
        .serialize_compressed(&mut out)
        .map_err(predicate_credential_system::Error::from)?;
    value
        .serialize_compressed(&mut out)
        .map_err(predicate_credential_system::Error::from)?;
    Ok(to_multibase(&out))
}

/// The inverse of [`labelled_text`].
///
/// # Errors
/// [`ProtoError::Pcs`] or [`ProtoError::Serialization`] if the text does not decode.
pub fn labelled_from_text<T: CanonicalDeserialize>(text: &str) -> Result<(String, T), ProtoError> {
    let bytes = from_multibase(text)?;
    let mut reader = bytes.as_slice();
    let label = Vec::<u8>::deserialize_compressed(&mut reader)
        .map_err(predicate_credential_system::Error::from)?;
    let label = String::from_utf8(label)
        .map_err(|_| ProtoError::Serialization("the label is not UTF-8".into()))?;
    let value =
        T::deserialize_compressed(&mut reader).map_err(predicate_credential_system::Error::from)?;
    if !reader.is_empty() {
        return Err(ProtoError::Serialization(
            "trailing bytes after the value".into(),
        ));
    }
    Ok((label, value))
}

/// A group element from its multibase text; the inverse of [`point_text`].
///
/// # Errors
/// [`ProtoError::Pcs`] if the text is not multibase base58btc, or the bytes are not a point in
/// the prime-order subgroup (decoding is validated).
pub fn point_from_text(text: &str) -> Result<G1, ProtoError> {
    Ok(from_bytes(&from_multibase(text)?)?)
}

/// Multibase text of a scalar (serials).
pub fn scalar_text(s: &Fr) -> Result<String, ProtoError> {
    Ok(to_multibase(&to_bytes(s)?))
}

/// A deterministic stream for deriving a member's PCS key from a 32-byte seed.
///
/// The VTA derives the seed from the context's derivation base (VTI-KEY-030) and feeds this to
/// the scheme's own key generation, so the same seed always yields the same `usk`, restarts
/// included. ChaCha20, as [`crate::issuer`] uses for the community's keys: the stream is fixed
/// by the seed on any build.
#[must_use]
pub fn seeded_rng(seed: &[u8; 32]) -> rand_chacha::ChaCha20Rng {
    use rand::SeedableRng;
    rand_chacha::ChaCha20Rng::from_seed(*seed)
}

/// A member's PCS secret key for `community`, derived from `seed` — the key
/// [`crate::vetter::VetterEngine::enrol_from_seed`] and
/// [`crate::applicant::ApplicantEngine::from_seed`] use.
///
/// The key is one per seed, whatever the period: the member's identifier under a period is
/// `Tag(usk, x_0)` at that period's helper key ([`member_id`]), and identifiers and tags under
/// two helper keys are unlinkable (`Protocol::register_reusing`).
///
/// What a VTA calls to rebuild a stored engine's key on every use, so the key itself is never
/// stored (design §13 C7).
///
/// # Errors
/// [`ProtoError::Pcs`] if the scheme instance cannot be set up.
pub fn member_key_from_seed(community: &str, seed: &[u8; 32]) -> Result<Usk, ProtoError> {
    let p = pcreds(community)?;
    Ok(<Bk as Backend>::tag_keygen(
        p.params(),
        &mut seeded_rng(seed),
    ))
}

/// The member `usk` registers as under the helper key `hvk`.
///
/// # Errors
/// [`ProtoError::Pcs`] if `hvk` is not a key of this deployment, or the tag is undefined.
pub fn member(pcreds: &Pcreds, hvk: &CheckedHvk, usk: &Usk) -> Result<Member, ProtoError> {
    Ok(pcreds.user(hvk, *usk)?)
}

/// The identifier of `usk` under the helper key `hvk`: `Tag(usk, x_0)`.
///
/// # Errors
/// As [`member`].
pub fn member_id(pcreds: &Pcreds, hvk: &CheckedHvk, usk: &Usk) -> Result<G1, ProtoError> {
    Ok(*member(pcreds, hvk, usk)?.id())
}

/// A vetter's binding as the community records and returns it (`pcs-binding/show`'s identifier,
/// `vta/pcs/vetter/recover`'s `boundId`): the vetter label, that period's helper key, and the
/// member's identifier under it. Under `pcreds` an identifier means something only under one
/// helper key, so the key travels with it; a VTA searching for the key behind `id` derives
/// identifiers under `hvk` ([`MemberIds::for_period`]). A wrong `hvk` can only make that search
/// fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingRef {
    pub label: String,
    pub hvk: Hvk,
    pub id: G1,
}

impl BindingRef {
    /// Multibase text ([`labelled_text`]).
    ///
    /// # Errors
    /// [`ProtoError::Pcs`] if a value cannot be encoded.
    pub fn to_text(&self) -> Result<String, ProtoError> {
        labelled_text(&self.label, &(self.hvk.clone(), self.id))
    }

    /// The inverse of [`Self::to_text`].
    ///
    /// # Errors
    /// [`ProtoError::Pcs`] or [`ProtoError::Serialization`] if the text does not decode.
    pub fn from_text(text: &str) -> Result<Self, ProtoError> {
        let (label, (hvk, id)) = labelled_from_text::<(Hvk, G1)>(text)?;
        Ok(Self { label, hvk, id })
    }
}

/// The PCS identifiers a community's scheme gives member keys under one period's helper key,
/// for many seeds in a row: what a VTA uses to search the keys it can derive for a context for
/// the one a community has bound (`vta/pcs/vetter/recover`). The scheme instance and the key are
/// checked once, not once per seed.
///
/// Holds no key: [`MemberIds::id_from_seed`] returns the public identifier and drops the
/// secret key it computed on the way.
pub struct MemberIds {
    pcreds: Pcreds,
    hvk: CheckedHvk,
}

impl MemberIds {
    /// The scheme instance for `community`, under the period key `hvk`.
    ///
    /// # Errors
    /// [`ProtoError::Pcs`] if the scheme instance cannot be set up or `hvk` is not one of its
    /// keys.
    pub fn for_period(community: &str, hvk: &Hvk) -> Result<Self, ProtoError> {
        let pcreds = pcreds(community)?;
        let hvk = pcreds.helper_key(hvk)?;
        Ok(Self { pcreds, hvk })
    }

    /// The identifier [`member_key_from_seed`] gives `seed` under this period's key.
    ///
    /// # Errors
    /// [`ProtoError::Pcs`] if the tag is undefined.
    pub fn id_from_seed(&self, seed: &[u8; 32]) -> Result<G1, ProtoError> {
        let usk = <Bk as Backend>::tag_keygen(self.pcreds.params(), &mut seeded_rng(seed));
        member_id(&self.pcreds, &self.hvk, &usk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    /// The search helper gives exactly the identifier the engines' own derivation does.
    #[test]
    fn member_ids_agree_with_member_key_from_seed() {
        let community = "did:example:community";
        let p = pcreds(community).unwrap();
        let helper = p.helper_keygen(
            predicate_credential_system::pcreds::Policy::threshold(1).unwrap(),
            &mut StdRng::seed_from_u64(1),
        );
        let ids = MemberIds::for_period(community, helper.key().vk()).unwrap();
        for i in 0u8..4 {
            let seed = [i; 32];
            let usk = member_key_from_seed(community, &seed).unwrap();
            let expected = member_id(&p, helper.key(), &usk).unwrap();
            assert_eq!(ids.id_from_seed(&seed).unwrap(), expected);
        }
    }

    #[test]
    fn key_lists_and_labelled_values_round_trip() {
        let keys: Vec<Fr> = vec![Fr::from(3u64), Fr::from(5u64)];
        let text = keys_text(&keys).unwrap();
        assert_eq!(keys_from_text::<Fr>(&text).unwrap(), keys);
        let t = labelled_text("vetter/2026-09", &Fr::from(7u64)).unwrap();
        let (label, v) = labelled_from_text::<Fr>(&t).unwrap();
        assert_eq!(label, "vetter/2026-09");
        assert_eq!(v, Fr::from(7u64));
    }
}
