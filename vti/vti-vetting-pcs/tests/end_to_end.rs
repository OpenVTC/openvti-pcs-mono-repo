//! End to end, one test per claim of the design (`design-docs/vetting-hidden-vetters-pcs.md`),
//! adversarial cases included, on `pcreds` with a helper key per vetter period. Counting is
//! VTI's own `requirements::evaluate`, unchanged.

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use rand::{SeedableRng, rngs::StdRng};
use serde_json::json;
use vta_sdk::{
    protocols::vetting::{VETTED_PREDICATE, VettingMethod, VettingRelationship},
    vetting::requirements::Need,
};
use vti_vetting_pcs::{
    ProtoError,
    applicant::{ApplicantEngine, ApplicantRef},
    meta::StatementMeta,
    scheme::{member_id, member_key_from_seed, point_text},
    token::TokenWallet,
    vetter::{HiddenAttestation, VetterEngine},
    vtc::{Decision, MAX_ATTESTATIONS, Vtc},
};

const COMMUNITY: &str = "did:example:kernel-vtc";
const R: usize = 3; // tokens per tick in these tests

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 22, 12, 0, 0).unwrap()
}

fn requirements() -> serde_json::Value {
    json!({
        "version": "0.1",
        "statementType": VETTED_PREDICATE,
        "minStatements": 2,
        "minByMethod": { "inPerson": 1 },
        "acceptedMethods": ["inPerson", "video", "priorAcquaintance"],
        "requiredClaims": ["name.legal"],
        "maxStatementAge": "P120D",
        "eligibleVetters": { "role": "vetter" },
        "independence": {
            "maxByDeclaredRelationship": { "family": 0 },
            "requireConsistentIdentityCommitment": true
        }
    })
}

struct World {
    rng: StdRng,
    vtc: Vtc,
    vetters: Vec<VetterEngine>,
}

/// A community in period 2026-09 with `n` enrolled vetters, each with one drip.
fn world(seed: u64, n: usize) -> World {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut vtc = Vtc::new(COMMUNITY, "2026-09", requirements(), &mut rng).unwrap();
    let mut vetters = Vec::new();
    for i in 0..n {
        let member = format!("member-{i}");
        vtc.grant(&member);
        let mut v = VetterEngine::new(&member, &vtc, &mut rng).unwrap();
        v.enroll(&mut vtc, &mut rng).unwrap();
        let label = vtc.current_token_label().to_string();
        v.drip(&mut vtc, 1, &label, R, &mut rng).unwrap();
        vetters.push(v);
    }
    World { rng, vtc, vetters }
}

fn applicant(w: &mut World, join_did: &str) -> ApplicantEngine {
    ApplicantEngine::new(&w.vtc.params().unwrap(), join_did, &mut w.rng).unwrap()
}

fn reference(w: &World, app: &ApplicantEngine) -> ApplicantRef {
    // Through its text, as the reference travels.
    let text = app
        .reference(&w.vtc.params().unwrap())
        .unwrap()
        .to_text()
        .unwrap();
    ApplicantRef::from_text(&text).unwrap()
}

fn meta(app: &ApplicantEngine, vtc: &Vtc, method: VettingMethod) -> StatementMeta {
    app.statement_meta(
        &vtc.params().unwrap(),
        vtc.requirements_digest(),
        StatementMeta {
            community: String::new(),
            requirements_digest: String::new(),
            method,
            claims_verified: vec!["name.legal".into()],
            liveness_confirmed: true,
            declared_relationship: VettingRelationship::None,
            identity_commitment: "zCommitmentOfThisApplication".into(),
            card_digest_multibase: "zCardDigest".into(),
            valid_from: NaiveDate::from_ymd_opt(2026, 9, 20).unwrap(),
            valid_until: NaiveDate::from_ymd_opt(2027, 1, 18).unwrap(),
            token_label: String::new(),
            token_serial: String::new(),
        },
    )
}

/// One vetting session: accept (reserves a token), human check, attest.
fn vet(w: &mut World, j: usize, app: &ApplicantEngine, method: VettingMethod) -> HiddenAttestation {
    let m = meta(app, &w.vtc, method);
    let applicant = reference(w, app);
    let r = w.vetters[j].accept(None, 2).unwrap();
    w.vetters[j]
        .attest(&w.vtc.params().unwrap(), &r, &applicant, m, &mut w.rng)
        .unwrap()
}

fn submit(w: &mut World, app: &ApplicantEngine) -> Result<Decision, ProtoError> {
    let c = w.vtc.challenge(&mut w.rng);
    let sub = app.submit(
        &w.vtc.params().unwrap(),
        w.vtc.requirements_digest(),
        &c,
        &mut w.rng,
    )?;
    w.vtc.submit(&sub, now())
}

// -------------------------------------------------------------------------------------------

#[test]
fn admits_on_two_hidden_vetters_and_names_none() {
    let mut w = world(1, 3);
    let mut bob = applicant(&mut w, "did:example:bob-kernel");
    let a = vet(&mut w, 0, &bob, VettingMethod::InPerson);
    bob.receive(&w.vtc.params().unwrap(), a).unwrap();
    let b = vet(&mut w, 1, &bob, VettingMethod::Video);
    bob.receive(&w.vtc.params().unwrap(), b).unwrap();

    let d = submit(&mut w, &bob).unwrap();
    assert!(d.evaluation.satisfied(), "{:?}", d.evaluation);
    assert_eq!(d.evaluation.distinct_vetters(), 2);

    // The facts the policy sees name no vetter: no member id, no vetter PCS id.
    let facts = serde_json::to_string(&d.statements).unwrap();
    let params = w.vtc.params().unwrap();
    for v in &w.vetters {
        assert!(!facts.contains(&v.member), "facts leak {}", v.member);
        let id = v.id(&params, "vetter/2026-09").unwrap();
        assert!(!facts.contains(&point_text(&id).unwrap()));
    }
    assert!(
        d.statements
            .iter()
            .all(|s| s.issuer.starts_with('z') && s.counted && s.verified)
    );
}

#[test]
fn request_more_then_admit_on_resubmission() {
    let mut w = world(2, 3);
    let mut bob = applicant(&mut w, "did:example:bob");
    let v = vet(&mut w, 1, &bob, VettingMethod::Video);
    bob.receive(&w.vtc.params().unwrap(), v).unwrap();

    let d = submit(&mut w, &bob).unwrap();
    assert!(!d.evaluation.satisfied());
    assert_eq!(
        d.evaluation.needs,
        vec![
            Need::Statements(1),
            Need::Method(VettingMethod::InPerson, 1)
        ]
    );

    let p = vet(&mut w, 0, &bob, VettingMethod::InPerson);
    bob.receive(&w.vtc.params().unwrap(), p).unwrap();
    let d = submit(&mut w, &bob).unwrap();
    assert!(d.evaluation.satisfied(), "{:?}", d.evaluation);
    // The first vetter's token came back with the same (id, tag): already counted, no anomaly.
    assert!(
        w.vtc.token_verifier().anomalies.is_empty(),
        "{:?}",
        w.vtc.token_verifier().anomalies
    );
}

#[test]
fn one_vetter_counts_once_across_submissions() {
    let mut w = world(3, 3);
    let mut bob = applicant(&mut w, "did:example:bob");
    let first = vet(&mut w, 0, &bob, VettingMethod::Video);
    bob.receive(&w.vtc.params().unwrap(), first).unwrap();
    submit(&mut w, &bob).unwrap();

    // The same vetter vets again, e.g. in person, and the client swaps it in.
    let second = vet(&mut w, 0, &bob, VettingMethod::InPerson);
    bob.replace(&w.vtc.params().unwrap(), second).unwrap();
    let d = submit(&mut w, &bob).unwrap();
    // Two statements on record, one tag: counted once.
    assert_eq!(d.statements.len(), 2);
    assert_eq!(d.evaluation.distinct_vetters(), 1);
    assert!(
        d.statements
            .iter()
            .any(|s| s.failures.contains(&"same-vetter".to_string()))
    );
}

#[test]
fn a_double_spent_token_does_not_count() {
    let mut w = world(4, 3);
    let mut alice = applicant(&mut w, "did:example:alice");
    let mut bob = applicant(&mut w, "did:example:bob");

    let for_alice = vet(&mut w, 0, &alice, VettingMethod::InPerson);
    let reused = for_alice.token.clone();
    alice.receive(&w.vtc.params().unwrap(), for_alice).unwrap();
    submit(&mut w, &alice).unwrap();

    // A cheating vetter reuses Alice's spent token for Bob.
    let m = meta(&bob, &w.vtc, VettingMethod::InPerson);
    let bob_ref = reference(&w, &bob);
    let cheat = w.vetters[0]
        .attest_with_token(&w.vtc.params().unwrap(), reused, &bob_ref, m, &mut w.rng)
        .unwrap();
    bob.receive(&w.vtc.params().unwrap(), cheat).unwrap(); // the signature itself is valid
    let honest = vet(&mut w, 1, &bob, VettingMethod::Video);
    bob.receive(&w.vtc.params().unwrap(), honest).unwrap();

    let d = submit(&mut w, &bob).unwrap();
    assert!(!d.evaluation.satisfied());
    assert_eq!(d.evaluation.distinct_vetters(), 1);
    assert!(
        d.statements
            .iter()
            .any(|s| s.failures.contains(&"token-double-spend".to_string()))
    );
    assert_eq!(
        w.vtc.token_verifier().anomalies.len(),
        1,
        "the VTC notices, without naming anyone"
    );
}

#[test]
fn tokens_and_metadata_cannot_move_between_attestations() {
    let mut w = world(5, 3);
    let mut bob = applicant(&mut w, "did:example:bob");
    let a = vet(&mut w, 0, &bob, VettingMethod::InPerson);
    bob.receive(&w.vtc.params().unwrap(), a).unwrap();
    let b = vet(&mut w, 1, &bob, VettingMethod::Video);
    bob.receive(&w.vtc.params().unwrap(), b).unwrap();

    // Swap the tokens only: the metadata names the other serial.
    let c = w.vtc.challenge(&mut w.rng);
    let mut sub = bob
        .submit(
            &w.vtc.params().unwrap(),
            w.vtc.requirements_digest(),
            &c,
            &mut w.rng,
        )
        .unwrap();
    let (t0, t1) = (sub.statements[0].1.clone(), sub.statements[1].1.clone());
    sub.statements[0].1 = t1;
    sub.statements[1].1 = t0;
    let d = w.vtc.submit(&sub, now()).unwrap();
    assert_eq!(d.evaluation.distinct_vetters(), 0);
    assert!(
        d.statements
            .iter()
            .all(|s| s.failures.contains(&"token-mismatch".to_string()))
    );

    // Swap the metadata too (claim "inPerson" for the video vetter): `π_iss` is bound to the
    // context of each attestation in order, so the request breaks.
    let c = w.vtc.challenge(&mut w.rng);
    let mut sub = bob
        .submit(
            &w.vtc.params().unwrap(),
            w.vtc.requirements_digest(),
            &c,
            &mut w.rng,
        )
        .unwrap();
    sub.statements.swap(0, 1);
    assert!(matches!(
        w.vtc.submit(&sub, now()),
        Err(ProtoError::ProofRejected(_))
    ));
}

#[test]
fn a_challenge_is_single_use_and_bound_to_the_proof() {
    let mut w = world(6, 2);
    let mut bob = applicant(&mut w, "did:example:bob");
    let a = vet(&mut w, 0, &bob, VettingMethod::InPerson);
    bob.receive(&w.vtc.params().unwrap(), a).unwrap();
    let c = w.vtc.challenge(&mut w.rng);
    let sub = bob
        .submit(
            &w.vtc.params().unwrap(),
            w.vtc.requirements_digest(),
            &c,
            &mut w.rng,
        )
        .unwrap();
    w.vtc.submit(&sub, now()).unwrap();
    assert_eq!(
        w.vtc.submit(&sub, now()).err(),
        Some(ProtoError::BadChallenge)
    );

    // A request made for one challenge (its `ssid`) does not verify under another.
    let c2 = w.vtc.challenge(&mut w.rng);
    let mut replay = sub.clone();
    replay.challenge = c2;
    assert!(matches!(
        w.vtc.submit(&replay, now()),
        Err(ProtoError::ProofRejected(_))
    ));
    // ... nor for another join DID: the binding of `id` to the persona is checked before the
    // proof, so swapping the DID is refused as a binding mismatch rather than a bad proof.
    let c3 = w.vtc.challenge(&mut w.rng);
    let mut other = bob
        .submit(
            &w.vtc.params().unwrap(),
            w.vtc.requirements_digest(),
            &c3,
            &mut w.rng,
        )
        .unwrap();
    other.join_did = "did:example:mallory".into();
    assert!(matches!(
        w.vtc.submit(&other, now()),
        Err(ProtoError::AttestationRejected(_))
    ));
    // And with a binding recomputed for the new DID, the request itself fails: `app_0` carries
    // it.
    let c4 = w.vtc.challenge(&mut w.rng);
    let mut forged = bob
        .submit(
            &w.vtc.params().unwrap(),
            w.vtc.requirements_digest(),
            &c4,
            &mut w.rng,
        )
        .unwrap();
    forged.join_did = "did:example:mallory".into();
    forged.id_binding = vti_vetting_pcs::meta::id_binding(
        &point_text(bob.id()).unwrap(),
        COMMUNITY,
        w.vtc.requirements_digest(),
        "did:example:mallory",
    );
    assert!(matches!(
        w.vtc.submit(&forged, now()),
        Err(ProtoError::ProofRejected(_))
    ));
}

#[test]
fn a_closed_token_label_means_no_token() {
    let mut w = world(7, 3);
    let mut bob = applicant(&mut w, "did:example:bob");
    let a = vet(&mut w, 0, &bob, VettingMethod::InPerson);
    bob.receive(&w.vtc.params().unwrap(), a).unwrap();
    let b = vet(&mut w, 1, &bob, VettingMethod::Video);
    bob.receive(&w.vtc.params().unwrap(), b).unwrap();
    let c = w.vtc.challenge(&mut w.rng);
    let sub = bob
        .submit(
            &w.vtc.params().unwrap(),
            w.vtc.requirements_digest(),
            &c,
            &mut w.rng,
        )
        .unwrap();

    let label = w.vtc.current_token_label().to_string();
    w.vtc.verifier.tokens.close_label(&label);
    let d = w.vtc.submit(&sub, now()).unwrap();
    assert_eq!(d.evaluation.distinct_vetters(), 0);
    assert!(
        d.statements
            .iter()
            .all(|s| s.failures.contains(&"no-token".to_string()))
    );
}

/// Periods are helper keys: an application lives in one period. It completes across a rotation
/// while its period is live; a vetter of the new period only cannot vet it; once its period is
/// dropped it fails as a whole, the applicant registers again, and each vetter refreshes its
/// statement under the new period with a NEW tag. An attestation of the old application forced
/// into the new request does not count.
#[test]
fn an_application_lives_in_one_period_and_refresh_carries_it_over() {
    let mut w = world(8, 3);
    let mut bob = applicant(&mut w, "did:example:bob");
    let old = vet(&mut w, 0, &bob, VettingMethod::InPerson);
    let old_tag = old.attestation.tag;
    bob.receive(&w.vtc.params().unwrap(), old.clone()).unwrap();

    // Rotate: 2026-10 is current, 2026-09 still live. Vetter 1 still holds its 2026-09
    // credential, so it can vet Bob's 2026-09 application.
    w.vtc.rotate("2026-10").unwrap();
    let label = w.vtc.current_token_label().to_string();
    w.vetters[1]
        .drip(&mut w.vtc, 31, &label, R, &mut w.rng)
        .unwrap();
    let new = vet(&mut w, 1, &bob, VettingMethod::Video);
    bob.receive(&w.vtc.params().unwrap(), new).unwrap();
    let d = submit(&mut w, &bob).unwrap();
    assert!(d.evaluation.satisfied(), "{:?}", d.evaluation);

    // A vetter enrolled under 2026-10 only cannot vet a 2026-09 application.
    w.vtc.grant("member-new");
    let mut fresh = VetterEngine::new("member-new", &w.vtc, &mut w.rng).unwrap();
    fresh.enroll(&mut w.vtc, &mut w.rng).unwrap();
    fresh.drip(&mut w.vtc, 31, &label, R, &mut w.rng).unwrap();
    let r = fresh.accept(None, 2).unwrap();
    let bob_ref = reference(&w, &bob);
    let m = meta(&bob, &w.vtc, VettingMethod::Video);
    assert_eq!(
        fresh
            .attest(&w.vtc.params().unwrap(), &r, &bob_ref, m, &mut w.rng)
            .err(),
        Some(ProtoError::NoCredentialForPeriod("vetter/2026-09".into()))
    );

    // 2026-09 is dropped: Bob's application fails as a whole.
    w.vtc.drop_period("2026-09").unwrap();
    assert_eq!(
        submit(&mut w, &bob).err(),
        Some(ProtoError::PeriodNotLive("vetter/2026-09".into()))
    );

    // Bob registers again under 2026-10; vetters 0 and 1 enrol under 2026-10 and refresh their
    // statements without a new session.
    let mut bob2 = applicant(&mut w, "did:example:bob");
    let bob2_ref = reference(&w, &bob2);
    for j in [0, 1] {
        w.vetters[j].enroll(&mut w.vtc, &mut w.rng).unwrap();
        w.vetters[j]
            .drip(&mut w.vtc, 32, &label, R, &mut w.rng)
            .unwrap();
        let refreshed = w.vetters[j]
            .refresh(&w.vtc.params().unwrap(), bob.id(), &bob2_ref, &mut w.rng)
            .unwrap();
        assert_ne!(
            refreshed.attestation.tag, old_tag,
            "tags under two periods' keys are unlinkable"
        );
        bob2.receive(&w.vtc.params().unwrap(), refreshed).unwrap();
    }
    let d = submit(&mut w, &bob2).unwrap();
    assert!(d.evaluation.satisfied(), "{:?}", d.evaluation);
    assert_eq!(d.evaluation.distinct_vetters(), 2);

    // The old application's attestation is refused on receipt, and forced into the new request
    // it does not verify.
    let mut forced = old;
    forced.label = "vetter/2026-10".into();
    assert!(matches!(
        bob2.receive(&w.vtc.params().unwrap(), forced.clone()),
        Err(ProtoError::AttestationRejected(_))
    ));
    let c = w.vtc.challenge(&mut w.rng);
    let sub = bob2
        .submit_attestations(
            &w.vtc.params().unwrap(),
            w.vtc.requirements_digest(),
            &c,
            &[&forced],
            &mut w.rng,
        )
        .unwrap();
    let d = w.vtc.submit(&sub, now()).unwrap();
    assert!(
        d.statements
            .iter()
            .any(|s| !s.verified && s.failures.contains(&"unverified".to_string()))
    );
}

#[test]
fn a_dropped_period_fails_the_whole_request() {
    let mut w = world(9, 3);
    let mut bob = applicant(&mut w, "did:example:bob");
    let a = vet(&mut w, 0, &bob, VettingMethod::InPerson);
    bob.receive(&w.vtc.params().unwrap(), a).unwrap();
    let c = w.vtc.challenge(&mut w.rng);
    let sub = bob
        .submit(
            &w.vtc.params().unwrap(),
            w.vtc.requirements_digest(),
            &c,
            &mut w.rng,
        )
        .unwrap();

    w.vtc.rotate("2026-10").unwrap();
    w.vtc.drop_period("2026-09").unwrap();
    assert_eq!(
        w.vtc.submit(&sub, now()).err(),
        Some(ProtoError::PeriodNotLive("vetter/2026-09".into()))
    );
}

#[test]
fn one_credential_per_member_and_period() {
    let mut w = world(10, 1);
    // Enrolling again under the same period with the same key is a client that lost the
    // answer: re-issued, and the tags are the same.
    w.vetters[0].enroll(&mut w.vtc, &mut w.rng).unwrap();
    // A second key for the same member in the same period is refused too: two credentials of one
    // period would count twice in one request.
    let mut twin = VetterEngine::new("member-0", &w.vtc, &mut w.rng).unwrap();
    assert!(matches!(
        twin.enroll(&mut w.vtc, &mut w.rng),
        Err(ProtoError::AlreadyIssued { .. })
    ));
    // Under the next period a credential is a new one, under a new key, whatever key it is on:
    // no request spans two periods.
    w.vtc.rotate("2026-10").unwrap();
    w.vetters[0].enroll(&mut w.vtc, &mut w.rng).unwrap();
    // Without a grant there is no credential.
    let mut stranger = VetterEngine::new("member-9", &w.vtc, &mut w.rng).unwrap();
    assert_eq!(
        stranger.enroll(&mut w.vtc, &mut w.rng).err(),
        Some(ProtoError::NotAVetter("member-9".into()))
    );
    // A removed vetter gets nothing under the next period.
    w.vtc.revoke("member-0");
    w.vtc.rotate("2026-11").unwrap();
    assert_eq!(
        w.vetters[0].enroll(&mut w.vtc, &mut w.rng).err(),
        Some(ProtoError::NotAVetter("member-0".into()))
    );
}

/// A root request is bound to its member: the community rebuilds the enrolment session for the
/// member that submits, so a request captured from one member and replayed by another fails and
/// cannot lock its owner out of the period.
#[test]
fn a_replayed_root_request_does_not_verify_for_another_member() {
    let mut w = world(17, 0);
    w.vtc.grant("member-a");
    w.vtc.grant("member-b");
    let a = VetterEngine::new("member-a", &w.vtc, &mut w.rng).unwrap();
    let params = w.vtc.params().unwrap();
    let (wire, _state) = a.enrolment_request(&params, "2026-09", &mut w.rng).unwrap();
    let (_, request) = wire.parse().unwrap();
    assert!(matches!(
        w.vtc.issue_vetter_root("member-b", &request, &mut w.rng),
        Err(ProtoError::Pcs(_))
    ));
    // ... and the owner can still enrol with it.
    w.vtc
        .issue_vetter_root("member-a", &request, &mut w.rng)
        .unwrap();
}

/// A vetter answers only a request that proves ownership of the applicant's identifier (`π_id`):
/// a reference with a tampered session, or someone else's identifier, is refused before any
/// token is spent.
#[test]
fn a_vetter_answers_only_a_proven_reference() {
    let mut w = world(18, 1);
    let bob = applicant(&mut w, "did:example:bob");
    let mallory = applicant(&mut w, "did:example:mallory");
    let m = meta(&bob, &w.vtc, VettingMethod::Video);
    let free = w.vetters[0].tokens_free();

    let mut tampered = reference(&w, &bob);
    tampered.ssid[0] ^= 1;
    let r = w.vetters[0].accept(None, 2).unwrap();
    assert!(matches!(
        w.vetters[0].attest(
            &w.vtc.params().unwrap(),
            &r,
            &tampered,
            m.clone(),
            &mut w.rng
        ),
        Err(ProtoError::Pcs(_))
    ));
    // Mallory's proof under Bob's identifier.
    let mut stolen = reference(&w, &mallory);
    stolen.request.id = *bob.id();
    assert!(matches!(
        w.vetters[0].attest(&w.vtc.params().unwrap(), &r, &stolen, m, &mut w.rng),
        Err(ProtoError::Pcs(_))
    ));
    // The token is still reserved, not spent: decline releases it.
    w.vetters[0].decline(&r);
    assert_eq!(w.vetters[0].tokens_free(), free);
    // The reference is the same text every time it is asked for.
    let p = w.vtc.params().unwrap();
    assert_eq!(
        bob.reference(&p).unwrap().to_text().unwrap(),
        bob.reference(&p).unwrap().to_text().unwrap()
    );
}

#[test]
fn a_submission_over_the_attestation_limit_is_refused_before_verification() {
    let mut w = world(19, 1);
    let mut bob = applicant(&mut w, "did:example:bob");
    let a = vet(&mut w, 0, &bob, VettingMethod::InPerson);
    bob.receive(&w.vtc.params().unwrap(), a).unwrap();
    let c = w.vtc.challenge(&mut w.rng);
    let mut sub = bob
        .submit(
            &w.vtc.params().unwrap(),
            w.vtc.requirements_digest(),
            &c,
            &mut w.rng,
        )
        .unwrap();
    let one = sub.request.attestations[0].clone();
    let statement = sub.statements[0].clone();
    for _ in 0..MAX_ATTESTATIONS {
        sub.request.attestations.push(one.clone());
        sub.statements.push(statement.clone());
    }
    assert_eq!(
        w.vtc.submit(&sub, now()).err(),
        Some(ProtoError::TooManyAttestations {
            count: MAX_ATTESTATIONS + 1,
            max: MAX_ATTESTATIONS
        })
    );
}

#[test]
fn withdrawal_by_tag_stops_counting_and_cannot_be_forged() {
    let mut w = world(11, 3);
    let mut bob = applicant(&mut w, "did:example:bob");
    let a = vet(&mut w, 0, &bob, VettingMethod::InPerson);
    bob.receive(&w.vtc.params().unwrap(), a).unwrap();
    let b = vet(&mut w, 1, &bob, VettingMethod::Video);
    bob.receive(&w.vtc.params().unwrap(), b).unwrap();
    assert!(submit(&mut w, &bob).unwrap().evaluation.satisfied());

    let label = bob.label().to_string();
    // Vetter 2 cannot withdraw vetter 1's statement: its proof is for its own tag.
    let (tag2, proof2) = w.vetters[2]
        .withdraw(&w.vtc.params().unwrap(), &label, bob.id(), &mut w.rng)
        .unwrap();
    let (tag1, proof1) = w.vetters[1]
        .withdraw(&w.vtc.params().unwrap(), &label, bob.id(), &mut w.rng)
        .unwrap();
    assert!(!w.vtc.withdraw(&label, bob.id(), &tag1, &proof2).unwrap());
    assert!(!w.vtc.withdraw(&label, bob.id(), &tag2, &proof1).unwrap() || tag1 == tag2);

    // Vetter 1 withdraws its own: no identity in the notice, only the tag and the proof.
    assert!(w.vtc.withdraw(&label, bob.id(), &tag1, &proof1).unwrap());
    let d = w.vtc.evaluate(&point_text(bob.id()).unwrap(), now());
    assert!(!d.evaluation.satisfied());
    assert!(
        d.statements
            .iter()
            .any(|s| s.revoked && s.failures.contains(&"revoked".to_string()))
    );
}

#[test]
fn drip_is_once_per_tick_and_reservations_bound_capacity() {
    let mut w = world(12, 1);
    let label = w.vtc.current_token_label().to_string();
    // A second fetch in the same tick is refused.
    assert!(matches!(
        w.vetters[0].drip(&mut w.vtc, 1, &label, R, &mut w.rng),
        Err(ProtoError::AlreadyServedThisTick { .. })
    ));
    // R tokens: R reservations, then atCapacity until the next tick.
    let rs: Vec<_> = (0..R)
        .map(|_| w.vetters[0].accept(None, 2).unwrap())
        .collect();
    assert_eq!(
        w.vetters[0].accept(None, 2).err(),
        Some(ProtoError::AtCapacity { available_from: 2 })
    );
    // A decline releases the token.
    w.vetters[0].decline(&rs[0]);
    assert!(w.vetters[0].accept(None, 2).is_ok());
    w.vetters[0]
        .drip(&mut w.vtc, 2, &label, R, &mut w.rng)
        .unwrap();
    assert_eq!(w.vetters[0].tokens_held(), 2 * R);

    // A personal limit below the drip: local, never sent, still refuses.
    let mut w = world(13, 1);
    w.vetters[0].personal_limit = Some(1);
    let bob = applicant(&mut w, "did:example:bob");
    vet(&mut w, 0, &bob, VettingMethod::InPerson);
    assert!(w.vetters[0].tokens_free() > 0);
    assert!(matches!(
        w.vetters[0].accept(None, 2),
        Err(ProtoError::AtCapacity { .. })
    ));
}

#[test]
fn opening_proofs_are_bound_to_their_request() {
    let mut w = world(14, 1);
    let label = w.vtc.current_token_label().to_string();
    let tvk = w.vtc.tvk(&label).unwrap().clone();
    let mut wallet = TokenWallet::new();
    // Proofs made for tick 5, presented for tick 6.
    let reqs = wallet
        .prepare(&tvk, &label, "member-0", 5, 2, &mut w.rng)
        .unwrap();
    assert_eq!(
        w.vtc.drip("member-0", 6, &label, &reqs, &mut w.rng).err(),
        Some(ProtoError::BadOpeningProof(0))
    );
    // ... or by another member.
    w.vtc.grant("member-7");
    assert_eq!(
        w.vtc.drip("member-7", 5, &label, &reqs, &mut w.rng).err(),
        Some(ProtoError::BadOpeningProof(0))
    );
}

#[test]
fn event_mode_needs_a_group_an_outside_approver_and_dies_after_the_event() {
    let mut w = world(15, 4);
    let members = ["member-0", "member-1", "member-2"];
    assert!(matches!(
        w.vtc.approve_event("summit", &members[..2], "admin", 3),
        Err(ProtoError::EventRefused(_))
    ));
    assert!(matches!(
        w.vtc.approve_event("summit", &members, "member-0", 3),
        Err(ProtoError::EventRefused(_))
    ));
    let event = w.vtc.approve_event("summit", &members, "admin", 3).unwrap();

    // Outside the group: refused. Inside: served.
    assert!(matches!(
        w.vetters[3].drip(&mut w.vtc, 2, &event, 20, &mut w.rng),
        Err(ProtoError::EventRefused(_))
    ));
    w.vetters[0]
        .drip(&mut w.vtc, 2, &event, 20, &mut w.rng)
        .unwrap();
    w.vetters[1]
        .drip(&mut w.vtc, 2, &event, 20, &mut w.rng)
        .unwrap();

    // Event tokens are preferred during the event and verify like any other.
    let mut bob = applicant(&mut w, "did:example:bob");
    let bob_ref = reference(&w, &bob);
    for (j, method) in [(0, VettingMethod::InPerson), (1, VettingMethod::Video)] {
        let m = meta(&bob, &w.vtc, method);
        let r = w.vetters[j].accept(Some(&event), 3).unwrap();
        assert_eq!(r.label, event);
        let att = w.vetters[j]
            .attest(&w.vtc.params().unwrap(), &r, &bob_ref, m, &mut w.rng)
            .unwrap();
        bob.receive(&w.vtc.params().unwrap(), att).unwrap();
    }
    let c = w.vtc.challenge(&mut w.rng);
    let late = bob
        .submit(
            &w.vtc.params().unwrap(),
            w.vtc.requirements_digest(),
            &c,
            &mut w.rng,
        )
        .unwrap();
    assert!(submit(&mut w, &bob).unwrap().evaluation.satisfied());

    // After the grace period the event label closes: 19 leftover event tokens are gone, the
    // monthly drip (R, untouched) remains.
    assert_eq!(w.vetters[0].tokens_held(), R + 19);
    w.vtc.close_event("summit");
    w.vetters[0].expire(&w.vtc);
    assert_eq!(w.vetters[0].tokens_held(), R);
    // A submission prepared under the event (its challenge `c` still unused) now fails on the
    // closed label: every statement is `no-token`, nothing counts.
    let d = w.vtc.submit(&late, now()).unwrap();
    assert_eq!(d.evaluation.distinct_vetters(), 0);
    assert!(
        d.statements
            .iter()
            .all(|s| s.failures.contains(&"no-token".to_string()))
    );
}

#[test]
fn engine_state_survives_a_restart() {
    let mut w = world(16, 2);
    let mut bob = applicant(&mut w, "did:example:bob");
    let a = vet(&mut w, 0, &bob, VettingMethod::InPerson);
    bob.receive(&w.vtc.params().unwrap(), a).unwrap();

    // Both engines round-trip through their storable forms.
    let params = w.vtc.params().unwrap();
    let bob_json = serde_json::to_string(&bob.snapshot().unwrap()).unwrap();
    let vetter_json = serde_json::to_string(&w.vetters[1].snapshot().unwrap()).unwrap();
    let mut bob =
        ApplicantEngine::restore(&serde_json::from_str(&bob_json).unwrap(), &params).unwrap();
    let before = point_text(&w.vetters[1].id(&params, "vetter/2026-09").unwrap()).unwrap();
    w.vetters[1] = VetterEngine::restore(&serde_json::from_str(&vetter_json).unwrap()).unwrap();

    // The restored vetter attests with the same key: a stable tag within a period is what stops
    // one vetter counting twice.
    let b = vet(&mut w, 1, &bob, VettingMethod::Video);
    bob.receive(&w.vtc.params().unwrap(), b).unwrap();
    assert_eq!(
        point_text(&w.vetters[1].id(&params, "vetter/2026-09").unwrap()).unwrap(),
        before
    );

    // And the restored applicant proves over the attestation it gathered before the restart.
    let d = submit(&mut w, &bob).unwrap();
    assert!(d.evaluation.satisfied(), "{:?}", d.evaluation);
    assert_eq!(d.evaluation.distinct_vetters(), 2);
}

/// A catch-up asks for several ticks in one pass, and a VTA stores the engine between every
/// request and its answer. Each answer has to find its own serials after that, whatever order
/// the answers arrive in.
#[test]
fn several_draws_in_flight_survive_a_snapshot_and_answer_in_any_order() {
    use vti_vetting_pcs::{issuer::TokenBatchWire, scheme::enc};

    let mut w = world(31, 1);
    let label = w.vtc.current_token_label().to_string();
    let params = w.vtc.params().unwrap();
    let held_before = w.vetters[0].tokens_held();

    let mut asked = Vec::new();
    for tick in [2u32, 3, 4] {
        asked.push(
            w.vetters[0]
                .drip_request(&params, tick, &label, R, &mut w.rng)
                .unwrap(),
        );
    }
    let snapshot = w.vetters[0].snapshot().unwrap();
    assert_eq!(snapshot.pending.len(), 3 * R);
    let mut restored = VetterEngine::restore(&snapshot).unwrap();
    assert_eq!(restored.draws_in_flight().len(), 3);

    // The community answers ticks 4 and 2; tick 3 it refuses, and its serials are dropped.
    for batch in [&asked[2], &asked[0]] {
        let reqs: Vec<_> = batch
            .requests
            .iter()
            .map(|r| r.to_request().unwrap())
            .collect();
        let pres = w
            .vtc
            .drip("member-0", batch.tick, &label, &reqs, &mut w.rng)
            .unwrap();
        let served = TokenBatchWire {
            label: label.clone(),
            tick: batch.tick,
            pre_credentials: pres.iter().map(|p| enc(p).unwrap()).collect(),
        };
        assert_eq!(restored.accept_drip(&params, &served).unwrap(), R);
    }
    restored.forget_draw(&label, 3);
    assert!(restored.draws_in_flight().is_empty());
    assert_eq!(restored.tokens_held(), held_before + 2 * R);
    assert!(restored.snapshot().unwrap().pending.is_empty());
}

/// A VTA never stores a member's `usk`: it derives a 32-byte seed from the context's base and
/// rebuilds the key from it on every use (§13 C7, VTI-KEY-030). That is sound only if the same
/// seed always gives the same key, and different seeds give different ones.
#[test]
fn a_seeded_key_is_the_same_key_every_time() {
    let mut rng = StdRng::seed_from_u64(0x5EED);
    let vtc = Vtc::new(COMMUNITY, "2026-09", requirements(), &mut rng).unwrap();
    let params = vtc.params().unwrap();
    let label = "vetter/2026-09";

    let a = VetterEngine::enrol_from_seed("member-a", &params, &[7; 32]).unwrap();
    let again = VetterEngine::enrol_from_seed("member-a", &params, &[7; 32]).unwrap();
    let other = VetterEngine::enrol_from_seed("member-a", &params, &[8; 32]).unwrap();
    assert_eq!(
        a.id(&params, label).unwrap(),
        again.id(&params, label).unwrap()
    );
    assert_ne!(
        a.id(&params, label).unwrap(),
        other.id(&params, label).unwrap()
    );
    assert_eq!(a.snapshot().unwrap().usk, again.snapshot().unwrap().usk);
    // Rebuilt from the seed and the community alone, as a VTA does on every use.
    let usk = member_key_from_seed(COMMUNITY, &[7; 32]).unwrap();
    assert_eq!(
        member_id(params.pcreds(), params.hvk(label).unwrap(), &usk).unwrap(),
        a.id(&params, label).unwrap()
    );

    let app = ApplicantEngine::from_seed(&params, "did:example:join", &[7; 32]).unwrap();
    let app_again = ApplicantEngine::from_seed(&params, "did:example:join", &[7; 32]).unwrap();
    assert_eq!(app.id(), app_again.id());
}
