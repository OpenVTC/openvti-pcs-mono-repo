//! The people in a vetting run: what each one does, step by step, in the
//! words of the TUI's keys (`ui/pages/main/components/vetting_panel/keys.rs`).

use std::time::Duration;

use anyhow::{Result, bail};
use clap::ArgMatches;

use super::{Driver, Exchange};
use crate::state_handler::actions::{Action, VettingAction as V};
use crate::state_handler::main_page::content::{DeskStage, DeskView, VettingMode, VettingTab};
use crate::state_handler::main_page::menu::MainMenu;
use crate::state_handler::state::State;

fn timeout(a: &ArgMatches) -> Duration {
    Duration::from_secs(*a.get_one::<u64>("timeout").expect("defaulted"))
}

/// Open the Vetting page on `tab`, as a person would from the menu.
async fn open_vetting(d: &mut Driver, tab: VettingTab) -> Result<()> {
    // The loading screen waits for Enter once the profile has loaded
    // (`ui/pages/loading`): wait for that, press it, then choose Vetting.
    use crate::state_handler::state::ActivePage;
    if !matches!(d.state().active_page, ActivePage::Main) {
        d.wait_for("the profile to load", |s| s.loading_complete.then_some(()))
            .await?;
        d.send(Action::DismissLoading)?;
    }
    d.wait_for("the main page", |s| {
        matches!(s.active_page, ActivePage::Main).then_some(())
    })
    .await?;
    for _ in 0..20 {
        if matches!(d.state().main_page.menu_panel.selected_menu, MainMenu::Vetting) {
            break;
        }
        d.send(Action::MainMenuSelected(MainMenu::Vetting))?;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    d.wait_for("the Vetting page", |s| {
        matches!(s.main_page.menu_panel.selected_menu, MainMenu::Vetting).then_some(())
    })
    .await?;
    if d.state().main_page.content_panel.vetting.tab != tab {
        d.vetting(V::SwitchTab)?;
        d.wait_for("the tab", |s| (s.main_page.content_panel.vetting.tab == tab).then_some(()))
            .await?;
    }
    Ok(())
}

/// Leave whatever form is open (Esc), back to the list.
async fn to_list(d: &mut Driver) -> Result<()> {
    for _ in 0..4 {
        if matches!(d.state().main_page.content_panel.vetting.mode, VettingMode::List)
            && d.state().main_page.content_panel.vetting.journey.is_none()
        {
            return Ok(());
        }
        if d.state().main_page.content_panel.vetting.journey.is_some() {
            d.vetting(V::CloseJourney)?;
        } else {
            d.vetting(V::Back)?;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    Ok(())
}

async fn desk_view(d: &mut Driver, view: DeskView) -> Result<()> {
    for _ in 0..4 {
        if d.state().main_page.content_panel.vetting.desk_view == view {
            return Ok(());
        }
        d.vetting(V::SwitchDeskView(true))?;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    d.wait_for("the desk view", |s| {
        (s.main_page.content_panel.vetting.desk_view == view).then_some(())
    })
    .await
}

fn vetting(s: &State) -> &crate::state_handler::main_page::content::VettingState {
    &s.main_page.content_panel.vetting
}

// ---------------------------------------------------------------------------
// Vetter
// ---------------------------------------------------------------------------

pub(super) async fn vetter(d: &mut Driver, a: &ArgMatches) -> Result<()> {
    d.step_timeout = timeout(a);
    let exchange = Exchange::new(a.get_one::<String>("exchange").expect("required"))?;
    let community = a.get_one::<String>("community").expect("required").clone();
    let name = a.get_one::<String>("name").expect("required").clone();
    let sessions = *a.get_one::<usize>("sessions").expect("defaulted");
    let hidden = a.get_flag("hidden");

    d.say(format!("{name}: open the vetting desk"));
    open_vetting(d, VettingTab::Desk).await?;
    d.wait_for("this persona's vetter grant from the community", |s| {
        vetting(s)
            .memberships
            .iter()
            .any(|m| m.community == community)
            .then_some(())
    })
    .await?;

    if hidden {
        d.say(format!("{name}: enrol for hidden vetting and draw tokens (k)"));
        d.vetting(V::DrawNow)?;
        d.wait_for("tokens to issue a ticket with", |s| {
            vetting(s)
                .hidden
                .iter()
                .any(|h| h.community == community && h.tokens_free > 0)
                .then_some(())
        })
        .await?;
    }

    d.say(format!("{name}: issue a ticket (Tickets, t, Enter)"));
    desk_view(d, DeskView::Tickets).await?;
    let ticket = issue_ticket(d, &community).await?;
    to_list(d).await?;
    println!("   ticket: {ticket}");
    exchange.put(&format!("ticket-{name}"), &ticket)?;
    run_sessions(d, &exchange, &community, &name, sessions).await
}

/// Issue a ticket. The client issues one only on a fresh answer from the
/// community about how it vets, and says "press t to try again" when it could
/// not get one (a listener still connecting, a slow reply): so does this.
async fn issue_ticket(d: &mut Driver, community: &str) -> Result<String> {
    let deadline = std::time::Instant::now() + d.step_timeout;
    loop {
        match try_issue_ticket(d, community).await {
            Ok(ticket) => return Ok(ticket),
            Err(e) if std::time::Instant::now() < deadline => {
                println!("   no ticket yet ({e}); pressing t again");
                to_list(d).await?;
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

async fn try_issue_ticket(d: &mut Driver, community: &str) -> Result<String> {
    let before = vetting(&d.state()).tickets.len();
    let saved = d.step_timeout;
    d.step_timeout = Duration::from_secs(90);
    let result = new_ticket(d, community, before).await;
    d.step_timeout = saved;
    result
}

async fn new_ticket(d: &mut Driver, community: &str, before: usize) -> Result<String> {
    let community = community.to_string();
    d.vetting(V::NewTicket)?;
    d.wait_for("the new-ticket form", |s| {
        matches!(vetting(s).mode, VettingMode::NewTicket { .. }).then_some(())
    })
    .await?;
    // The form opens on the first community this persona vets for; move to ours.
    for _ in 0..vetting(&d.state()).memberships.len() {
        let on_ours = match vetting(&d.state()).mode {
            VettingMode::NewTicket { membership_index, .. } => vetting(&d.state())
                .memberships
                .get(membership_index)
                .is_some_and(|m| m.community == community),
            _ => false,
        };
        if on_ours {
            break;
        }
        d.vetting(V::Cycle(true))?;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    d.vetting(V::Submit)?;
    let ticket = d
        .wait_for("the ticket", |s| {
            let tickets = &vetting(s).tickets;
            (tickets.len() > before)
                .then(|| tickets.iter().find(|t| t.community == community && t.live))
                .flatten()
                .map(|t| t.uri.clone().unwrap_or_else(|| t.code.clone()))
        })
        .await?;
    Ok(ticket)
}

/// Run each session that arrives on the ticket, through to the statement.
async fn run_sessions(
    d: &mut Driver,
    exchange: &Exchange,
    community: &str,
    name: &str,
    sessions: usize,
) -> Result<()> {
    let community = community.to_string();
    for n in 1..=sessions {
        d.say(format!("{name}: wait for applicant #{n}'s request (Requests)"));
        desk_view(d, DeskView::Requests).await?;
        let request = d
            .wait_for("a vetting request", |s| {
                vetting(s)
                    .desk
                    .iter()
                    .find(|r| r.community == community && r.stage == DeskStage::Accepted)
                    .map(|r| r.request_id.clone())
            })
            .await?;
        select_request(d, &request).await?;

        d.say(format!("{name}: open the session (o, Enter)"));
        d.vetting(V::OpenSession)?;
        d.wait_for("the session form", |s| {
            matches!(vetting(s).mode, VettingMode::OpenSession { .. }).then_some(())
        })
        .await?;
        d.vetting(V::Submit)?;
        d.wait_for("the applicant's card", |s| {
            vetting(s)
                .desk
                .iter()
                .find(|r| r.request_id == request)
                .is_some_and(|r| r.stage == DeskStage::Card)
                .then_some(())
        })
        .await?;
        to_list(d).await?;
        let row = vetting(&d.state())
            .desk
            .iter()
            .find(|r| r.request_id == request)
            .cloned()
            .expect("seen above");
        println!(
            "   card from {}: match code {:?}, claims {:?}",
            row.applicant_name.as_deref().unwrap_or(&row.applicant),
            row.match_code,
            row.claims
        );

        d.say(format!("{name}: check the person and attest (a)"));
        select_request(d, &request).await?;
        let issued_before = vetting(&d.state()).issued.len();
        let hidden_before = vetting(&d.state()).attested_hidden.len();
        d.vetting(V::StartAttest)?;
        d.wait_for("the attestation form", |s| {
            matches!(vetting(s).mode, VettingMode::Attest { .. }).then_some(())
        })
        .await?;
        fill_attestation(d).await?;
        d.vetting(V::Submit)?;
        d.wait_for("the statement to be issued", |s| {
            (vetting(s).issued.len() > issued_before
                || vetting(s).attested_hidden.len() > hidden_before)
                .then_some(())
        })
        .await?;
        to_list(d).await?;
        exchange.put(&format!("attested-{name}-{n}"), &request)?;
    }
    d.say(format!("{name}: done"));
    Ok(())
}

async fn select_request(d: &mut Driver, request: &str) -> Result<()> {
    let Some(index) = vetting(&d.state())
        .desk
        .iter()
        .position(|r| r.request_id == request)
    else {
        bail!("request {request} is not on the desk");
    };
    d.vetting(V::Select(index))?;
    d.wait_for("the request selected", |s| {
        (vetting(s).selected == index).then_some(())
    })
    .await
}

/// The human check, as the vetter records it: in person, the document seen,
/// no prior relationship, liveness confirmed, and the attestation ticked.
async fn fill_attestation(d: &mut Driver) -> Result<()> {
    let form = |d: &Driver| match &vetting(&d.state()).mode {
        VettingMode::Attest { form, .. } => Some(form.clone()),
        _ => None,
    };
    // Field 1: the document relied on. The list starts with "none", which a
    // documentary method refuses; take the first real document.
    while form(d).is_some_and(|f| f.field < 1) {
        d.vetting(V::NextField)?;
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    if vetting(&d.state()).documentation.len() > 1
        && form(d).is_some_and(|f| f.documentation_index == 0)
    {
        d.vetting(V::Cycle(true))?;
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    while form(d).is_some_and(|f| f.field < 3) {
        d.vetting(V::NextField)?;
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    if form(d).is_some_and(|f| !f.liveness_confirmed) {
        d.vetting(V::Toggle)?;
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    d.vetting(V::NextField)?;
    tokio::time::sleep(Duration::from_millis(150)).await;
    if form(d).is_some_and(|f| !f.attested) {
        d.vetting(V::Toggle)?;
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    let f = form(d);
    println!("   attestation form: {f:?}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Applicant
// ---------------------------------------------------------------------------

pub(super) async fn applicant(d: &mut Driver, a: &ArgMatches) -> Result<()> {
    d.step_timeout = timeout(a);
    let exchange = Exchange::new(a.get_one::<String>("exchange").expect("required"))?;
    let community = a.get_one::<String>("community").expect("required").clone();
    let vetters: Vec<String> = a
        .get_many::<String>("vetters")
        .expect("required")
        .cloned()
        .collect();
    let hidden = a.get_flag("hidden");

    d.say("applicant: start an application (Applications, n)");
    open_vetting(d, VettingTab::Applications).await?;
    if vetting(&d.state()).personas.is_empty() {
        super::persona::create_persona(d, "applicant").await?;
        d.wait_for("the persona on the Vetting page", |s| {
            (!vetting(s).personas.is_empty()).then_some(())
        })
        .await?;
    }
    let application = match find_application(&d.state(), &community) {
        Some(id) => id,
        None => {
            d.vetting(V::StartApplication)?;
            d.wait_for("the new-application form", |s| {
                matches!(vetting(s).mode, VettingMode::NewApplication { .. }).then_some(())
            })
            .await?;
            d.vetting(V::Input(community.clone()))?;
            d.vetting(V::Submit)?;
            // The form moves through its fields (community, persona, context);
            // Enter on each takes the default.
            for _ in 0..4 {
                if find_application(&d.state(), &community).is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(800)).await;
                if matches!(vetting(&d.state()).mode, VettingMode::NewApplication { .. }) {
                    d.vetting(V::Submit)?;
                }
            }
            d.wait_for("the application", |s| find_application(s, &community))
                .await?
        }
    };
    println!("   application {application}");
    to_list(d).await?;

    if hidden {
        d.say("applicant: take the hidden (PCS) vetting path (p)");
        select_application(d, &application).await?;
        if !app(&d.state(), &application).is_some_and(|r| r.pcs_zkp) {
            d.vetting(V::SwitchVettingPath)?;
        }
        d.wait_for("the hidden path", |s| {
            app(s, &application).is_some_and(|r| r.pcs_zkp).then_some(())
        })
        .await?;
    }

    d.say("applicant: choose the face the vetters see (f)");
    choose_face(d, &application).await?;

    for vetter in &vetters {
        d.say(format!("applicant: ask {vetter} with their ticket (r)"));
        let ticket = exchange.take(&format!("ticket-{vetter}"), d.step_timeout).await?;
        select_application(d, &application).await?;
        d.vetting(V::RequestVetter)?;
        d.wait_for("the request form", |s| {
            matches!(vetting(s).mode, VettingMode::RequestVetter { .. }).then_some(())
        })
        .await?;
        d.vetting(V::PasteTicket(ticket))?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        d.vetting(V::Submit)?;
        let requests_before = app(&d.state(), &application).map_or(0, |r| r.requests.len());
        d.wait_for("the request to be sent", |s| {
            app(s, &application)
                .is_some_and(|r| r.requests.len() > requests_before)
                .then_some(())
        })
        .await
        .or_else(|e| {
            // A request may already be listed if the form closed fast.
            if app(&d.state(), &application).is_some_and(|r| !r.requests.is_empty()) {
                Ok(())
            } else {
                Err(e)
            }
        })?;
        to_list(d).await?;
    }

    for n in 1..=vetters.len() {
        d.say(format!("applicant: send my card to session #{n} (c)"));
        let statements_before = app(&d.state(), &application).map_or(0, |r| r.statements);
        d.wait_for("a session opened by a vetter", |s| {
            app(s, &application)
                .and_then(|r| r.requests.iter().find(|q| q.card_session.is_some()))
                .map(|_| ())
        })
        .await?;
        select_application(d, &application).await?;
        d.vetting(V::ReviewCard)?;
        d.wait_for("the card preview", |s| match &vetting(s).mode {
            VettingMode::SendCard { preview: Some(_), .. } => Some(()),
            _ => None,
        })
        .await?;
        if let VettingMode::SendCard { preview: Some(p), .. } = &vetting(&d.state()).mode {
            println!("   card preview: {p:?}");
        }
        d.vetting(V::Submit)?;
        d.say(format!("applicant: wait for statement #{n}"));
        d.wait_for("the vetter's statement", |s| {
            app(s, &application)
                .is_some_and(|r| r.statements > statements_before)
                .then_some(())
        })
        .await?;
        to_list(d).await?;
    }

    d.say("applicant: requirements met — join (j)");
    d.wait_for("the requirements to be met", |s| {
        app(s, &application).is_some_and(|r| r.satisfied).then_some(())
    })
    .await?;
    d.send(Action::StartJoinFor(community.clone()))?;
    super::join::finish_join(d, &community).await?;
    exchange.put("admitted-applicant", &application)?;
    d.say("applicant: admitted");
    Ok(())
}

fn find_application(s: &State, community: &str) -> Option<String> {
    vetting(s)
        .applications
        .iter()
        .find(|a| a.community == community)
        .map(|a| a.id.clone())
}

fn app<'a>(
    s: &'a State,
    id: &str,
) -> Option<&'a crate::state_handler::main_page::content::ApplicationRow> {
    vetting(s).applications.iter().find(|a| a.id == id)
}

async fn select_application(d: &mut Driver, id: &str) -> Result<()> {
    let Some(index) = vetting(&d.state()).applications.iter().position(|a| a.id == id) else {
        bail!("application {id} is not listed");
    };
    d.vetting(V::Select(index))?;
    d.wait_for("the application selected", |s| {
        (vetting(s).selected == index).then_some(())
    })
    .await
}

/// Choose a face carrying the claims the community requires; make one if
/// there is none (the new-face form, filling each required claim).
async fn choose_face(d: &mut Driver, application: &str) -> Result<()> {
    if app(&d.state(), application).is_some_and(|r| r.face.is_some()) {
        return Ok(());
    }
    select_application(d, application).await?;
    d.vetting(V::ChooseFace)?;
    d.wait_for("the face chooser", |s| {
        matches!(
            vetting(s).mode,
            VettingMode::ChooseFace { .. } | VettingMode::NewFace(_)
        )
        .then_some(())
    })
    .await?;
    // The last choice in the chooser is "a new face".
    if let VettingMode::ChooseFace { faces, .. } = &vetting(&d.state()).mode
        && faces.is_empty()
    {
        d.vetting(V::Submit)?;
        d.wait_for("the new-face form", |s| {
            matches!(vetting(s).mode, VettingMode::NewFace(_)).then_some(())
        })
        .await?;
    }
    if matches!(vetting(&d.state()).mode, VettingMode::NewFace(_)) {
        super::face::fill_new_face(d).await?;
    } else {
        d.vetting(V::Submit)?;
    }
    d.wait_for("a face on the application", |s| {
        app(s, application).and_then(|r| r.face.clone())
    })
    .await?;
    to_list(d).await
}
