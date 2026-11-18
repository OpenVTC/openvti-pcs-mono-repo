//! Joining once the application meets the community's requirements: the join
//! flow's vetting page, Enter on the highlighted way in (for an application
//! that meets the requirements, joining as its persona with its statements),
//! and the verdict.

use std::time::Duration;

use anyhow::Result;

use super::Driver;
use crate::state_handler::actions::Action;
use crate::state_handler::join::{JoinPage, JoinRoute, VettingPhase};
use crate::state_handler::state::State;

fn routes_shown(s: &State) -> bool {
    matches!(s.join.page, JoinPage::Vetting)
        && s.join
            .vetting
            .as_ref()
            .is_some_and(|v| !matches!(v.phase, VettingPhase::Asking))
}

fn admitted(s: &State, community: &str) -> bool {
    // The main page scopes itself to an active membership as soon as one
    // exists; an applicant with no other community has this one exactly when
    // it has been admitted.
    s.selected_community
        .as_ref()
        .is_some_and(|(vtc, _)| vtc == community)
}

pub(super) async fn finish_join(d: &mut Driver, community: &str) -> Result<()> {
    d.wait_for("the join flow's ways in", |s| routes_shown(s).then_some(()))
        .await?;
    // Highlight the vetting route (the application's own row: join as its
    // persona, its statements attached), as ↓/↑ would.
    if let Some(VettingPhase::Known(known)) = d.state().join.vetting.as_ref().map(|v| &v.phase) {
        for (i, r) in known.routes.iter().enumerate() {
            println!(
                "   route {i}{}: {:?} — {} ({})",
                if i == known.row { " (highlighted)" } else { "" },
                r.route,
                r.label,
                if r.available() {
                    "available"
                } else {
                    r.blocked().unwrap_or("blocked")
                }
            );
        }
        let target = known
            .routes
            .iter()
            .position(|r| r.route == JoinRoute::Vetting && r.available());
        if let Some(target) = target {
            for _ in 0..known.routes.len() {
                let row = match d.state().join.vetting.as_ref().map(|v| &v.phase) {
                    Some(VettingPhase::Known(k)) => k.row,
                    _ => break,
                };
                if row == target {
                    break;
                }
                d.send(Action::JoinVettingRow(row < target))?;
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    }
    let mut printed = 0;
    // Enter on the highlighted way in. The page answers a blocked route with
    // why, and a step that is still running with nothing: so read what it says,
    // and press again while the join has not gone out.
    for _ in 0..10 {
        d.send(Action::JoinVettingTake)?;
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            d.flush_log();
            let s = d.state();
            for m in s.join.messages.iter().skip(printed) {
                println!("   join: {m:?}");
            }
            printed = s.join.messages.len();
            if admitted(&s, community) || s.join.processing || !routes_shown(&s) {
                break;
            }
        }
        let s = d.state();
        if admitted(&s, community) || s.join.processing || !routes_shown(&s) {
            break;
        }
    }
    // The pages that follow the route, each answered as a person joining with
    // no invitation and no wallet would: join without an invitation, the
    // offered context, the face already worn, the registry as offered, no
    // wallet. Each is pressed once per page, and again if the page stays.
    let deadline = std::time::Instant::now() + d.step_timeout;
    let mut last: Option<(String, std::time::Instant)> = None;
    while std::time::Instant::now() < deadline {
        d.flush_log();
        let s = d.state();
        for m in s.join.messages.iter().skip(printed) {
            println!("   join: {m:?}");
        }
        printed = s.join.messages.len();
        if admitted(&s, community) {
            return Ok(());
        }
        if !matches!(s.active_page, crate::state_handler::state::ActivePage::Join) {
            break;
        }
        let page = format!("{:?}", s.join.page);
        let due = match &last {
            Some((p, at)) => *p != page || at.elapsed() > Duration::from_secs(15),
            None => true,
        };
        if due && !s.join.processing {
            let action = match s.join.page {
                JoinPage::InvitationChoice => {
                    let without = s.join.invitation_without_row();
                    if s.join.invitation_use_selected != without {
                        d.send(Action::JoinInvitationSelect(without))?;
                        tokio::time::sleep(Duration::from_millis(300)).await;
                    }
                    Some(("invitation: join without", Action::JoinInvitationChoose))
                }
                JoinPage::IdentityChoice if s.join.reuse_confirm.is_some() => {
                    Some(("reuse persona: yes", Action::JoinReuseConfirm))
                }
                JoinPage::IdentityChoice => Some(("persona: Enter", Action::JoinIdentityChoose)),
                JoinPage::ContextChoice => Some(("context: Enter", Action::JoinContextChoose)),
                JoinPage::Answers => Some(("answers: Enter", Action::JoinAnswersChoose)),
                JoinPage::RegistryConsent => Some(("registry: Enter", Action::JoinRegistryConfirm)),
                JoinPage::Wallet => Some(("wallet: skip", Action::JoinWalletSkip)),
                JoinPage::Vetting => Some(("route: Enter", Action::JoinVettingTake)),
                _ => None,
            };
            if let Some((what, action)) = action {
                println!("   join page {page}: {what}");
                d.send(action)?;
            }
            last = Some((page, std::time::Instant::now()));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let mut page = String::new();
    d.wait_for("the community's verdict (admission)", |s| {
        for m in s.join.messages.iter().skip(printed) {
            println!("   join: {m:?}");
        }
        printed = s.join.messages.len();
        let now = format!(
            "{:?} on {:?} (processing: {})",
            s.active_page, s.join.page, s.join.processing
        );
        if now != page {
            println!("   join page now: {now}");
            page = now;
        }
        admitted(s, community).then_some(())
    })
    .await
}
