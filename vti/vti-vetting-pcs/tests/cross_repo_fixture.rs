//! The community's verifier against a frozen submission, read back from its wire form.
//!
//! `tests/fixtures/submission.json` is a submission built by the member-side engines (as a VTA
//! runs them for the openvtc client), written in the wire form a join request carries
//! (`extensions.hiddenVetting`) beside the parameters the community published. It is produced
//! by [`regenerate_fixture`] (`cargo test -p vti-vetting-pcs --test cross_repo_fixture --
//! --ignored`) and then frozen: if the wire format, the contexts or the token encoding drift,
//! these tests fail until the fixture is regenerated on purpose.
//!
//! Only public parameters are read back: the verifier here never sees the community's keys.

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use rand::{SeedableRng, rngs::StdRng};
use serde_json::json;
use vta_sdk::protocols::vetting::{
    VETTED_PREDICATE, VettingMethod, VettingRelationship, VettingRequirements,
};
use vti_vetting_pcs::{
    applicant::ApplicantEngine,
    meta::StatementMeta,
    scheme::{Hvk, Tvk, keys_from_text, keys_text},
    token::TokenVerifier,
    verifier::{Verifier, VerifierParams},
    vetter::VetterEngine,
    vtc::Vtc,
    wire::SubmissionWire,
};

const FIXTURE: &str = include_str!("fixtures/submission.json");
const COMMUNITY: &str = "did:webvh:QmVtcScid:kernel-vtc.example";

struct Fixture {
    verifier: Verifier,
    submission: vti_vetting_pcs::verifier::Submission,
    now: DateTime<Utc>,
    satisfied: bool,
    distinct: usize,
}

fn strings(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect()
}

fn load() -> Fixture {
    let f: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture parses");
    let community = f["community"].as_str().unwrap().to_string();
    let requirements: VettingRequirements =
        serde_json::from_value(f["requirements"].clone()).expect("requirements parse");
    let hvks: Vec<Hvk> = keys_from_text(f["helperKey"].as_str().unwrap()).unwrap();
    let tvks: Vec<Tvk> = keys_from_text(f["tokenKey"].as_str().unwrap()).unwrap();
    let vetter_labels = strings(&f["vetterLabels"]);
    let token_labels = strings(&f["tokenLabels"]);
    let verifier = Verifier::new(
        VerifierParams {
            community: community.clone(),
            audience: community,
            requirements,
            requirements_digest: f["requirementsDigest"].as_str().unwrap().to_string(),
        },
        vetter_labels.into_iter().zip(hvks).collect(),
        TokenVerifier::new(token_labels.into_iter().zip(tvks)),
    )
    .unwrap();
    let wire = SubmissionWire::from_extensions(&f["extensions"])
        .expect("extensions decode")
        .expect("the hiddenVetting member is present");
    Fixture {
        verifier,
        submission: wire.to_submission().expect("submission decodes"),
        now: DateTime::parse_from_rfc3339(f["now"].as_str().unwrap())
            .unwrap()
            .with_timezone(&Utc),
        satisfied: f["expect"]["satisfied"].as_bool().unwrap(),
        distinct: f["expect"]["distinctVetters"].as_u64().unwrap() as usize,
    }
}

#[test]
fn the_vtc_accepts_a_submission_built_by_the_member_engines() {
    let mut f = load();
    let decision = f
        .verifier
        .submit(&f.submission, f.now)
        .expect("the request verifies under the published parameters");
    assert_eq!(decision.evaluation.satisfied(), f.satisfied);
    assert_eq!(decision.evaluation.distinct_vetters(), f.distinct);
    assert!(decision.statements.iter().all(|s| s.counted));
}

#[test]
fn the_facts_the_policy_sees_name_no_vetter() {
    let mut f = load();
    let decision = f.verifier.submit(&f.submission, f.now).unwrap();
    let facts = serde_json::to_string(&decision.statements).unwrap();
    // Every issuer is a tag (multibase), never a DID.
    for s in &decision.statements {
        assert!(
            s.issuer.starts_with('z'),
            "issuer {} is not a tag",
            s.issuer
        );
    }
    assert!(!facts.contains("did:"), "a DID reached the facts: {facts}");
}

#[test]
fn a_replayed_submission_spends_its_tokens_once() {
    let mut f = load();
    let first = f.verifier.submit(&f.submission, f.now).unwrap();
    assert_eq!(first.evaluation.distinct_vetters(), f.distinct);
    // The same submission again: the serials are already spent under the same (id, tag), which
    // is the `requestMore` resubmission case, so it counts the same and raises no anomaly.
    let again = f.verifier.submit(&f.submission, f.now).unwrap();
    assert_eq!(again.evaluation.distinct_vetters(), f.distinct);
    assert!(f.verifier.tokens.anomalies.is_empty());
}

#[test]
fn a_tampered_statement_breaks_the_request() {
    let mut f = load();
    // Claim a different method for the first statement: `π_iss` is bound to the metadata of
    // every statement, so the whole request is refused.
    f.submission.statements[0].0.method = VettingMethod::Video;
    let err = f
        .verifier
        .submit(&f.submission, f.now)
        .expect_err("a rewritten statement must not verify");
    assert!(
        matches!(err, vti_vetting_pcs::ProtoError::ProofRejected(_)),
        "unexpected error: {err}"
    );
}

/// Writes `tests/fixtures/submission.json`: a community in period 2026-09, two vetters (one in
/// person, one by video), and the applicant's submission in its wire form.
#[test]
#[ignore = "regenerates the frozen fixture; run on purpose after a wire change"]
fn regenerate_fixture() {
    let requirements = json!({
        "version": "0.1",
        "statementType": VETTED_PREDICATE,
        "minStatements": 2,
        "minByMethod": { "inPerson": 1 },
        "acceptedMethods": ["inPerson", "video"],
        "requiredClaims": ["name.legal"],
        "eligibleVetters": { "role": "vetter" }
    });
    let mut rng = StdRng::seed_from_u64(20260922);
    let mut vtc = Vtc::new(COMMUNITY, "2026-09", requirements.clone(), &mut rng).unwrap();
    let label = vtc.current_token_label().to_string();
    let mut vetters = Vec::new();
    for i in 0..2 {
        let member = format!("did:example:vetter-{i}");
        vtc.grant(&member);
        let mut v = VetterEngine::new(&member, &vtc, &mut rng).unwrap();
        v.enroll(&mut vtc, &mut rng).unwrap();
        v.drip(&mut vtc, 1, &label, 3, &mut rng).unwrap();
        vetters.push(v);
    }
    let params = vtc.params().unwrap();
    let join_did = "did:example:applicant-join";
    let mut app = ApplicantEngine::new(&params, join_did, &mut rng).unwrap();
    let reference = app.reference(&params).unwrap();
    for (v, method) in vetters
        .iter_mut()
        .zip([VettingMethod::InPerson, VettingMethod::Video])
    {
        let meta = app.statement_meta(
            &params,
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
        );
        let r = v.accept(None, 2).unwrap();
        let att = v.attest(&params, &r, &reference, meta, &mut rng).unwrap();
        app.receive(&params, att).unwrap();
    }
    let challenge = vtc.challenge(&mut rng);
    let sub = app
        .submit(&params, vtc.requirements_digest(), &challenge, &mut rng)
        .unwrap();
    let wire = SubmissionWire::from_submission(&sub).unwrap();
    let vetter_labels = params.vetter_labels();
    let token_labels: Vec<String> = params.tokens().live_labels().iter().cloned().collect();
    let hvks: Vec<Hvk> = vetter_labels
        .iter()
        .map(|l| params.hvk(l).unwrap().vk().clone())
        .collect();
    let tvks: Vec<Tvk> = token_labels
        .iter()
        .map(|l| params.tokens().tvk(l).unwrap().clone())
        .collect();
    let fixture = json!({
        "README": "Frozen by tests/cross_repo_fixture.rs::regenerate_fixture. Do not edit by hand.",
        "community": COMMUNITY,
        "requirements": requirements,
        "requirementsDigest": vtc.requirements_digest(),
        "helperKey": keys_text(&hvks).unwrap(),
        "tokenKey": keys_text(&tvks).unwrap(),
        "vetterLabels": vetter_labels,
        "tokenLabels": token_labels,
        "now": Utc.with_ymd_and_hms(2026, 9, 22, 12, 0, 0).unwrap().to_rfc3339(),
        "extensions": wire.to_extensions().unwrap(),
        "expect": { "satisfied": true, "distinctVetters": 2 },
    });
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/submission.json"
    );
    std::fs::write(path, serde_json::to_string_pretty(&fixture).unwrap() + "\n").unwrap();
}
