//! Creating a persona (My Identity → new persona), as the TUI's overlay does:
//! type a label, then Enter through the path and context phases until the DID
//! is minted.

use std::time::Duration;

use anyhow::{Result, bail};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::Driver;
use crate::state_handler::actions::Action;
use crate::state_handler::main_page::content::CreatePersonaPhase;

pub(super) async fn create_persona(d: &mut Driver, label: &str) -> Result<String> {
    d.say(format!("create a persona “{label}” (My Identity)"));
    d.send(Action::StartCreatePersona)?;
    d.wait_for("the new-persona overlay", |s| {
        s.main_page.create_persona.as_ref().map(|_| ())
    })
    .await?;
    for c in label.chars() {
        d.send(Action::CreatePersonaInput(KeyEvent::new(
            KeyCode::Char(c),
            KeyModifiers::NONE,
        )))?;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut printed = 0;
    for _ in 0..40 {
        let Some(overlay) = d.state().main_page.create_persona.clone() else {
            bail!("the new-persona overlay closed");
        };
        for m in overlay.messages.iter().skip(printed) {
            println!("   persona: {m}");
        }
        printed = overlay.messages.len();
        match overlay.phase {
            CreatePersonaPhase::Done => {
                let did = overlay.did.clone().unwrap_or_default();
                d.send(Action::CreatePersonaClose)?;
                println!("   persona DID: {did}");
                return Ok(did);
            }
            CreatePersonaPhase::Failed => bail!("creating the persona failed: {:?}", overlay.messages),
            CreatePersonaPhase::Working => {}
            // Label and path: Enter takes what is there (the server names the path).
            _ => d.send(Action::CreatePersonaSubmit)?,
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("creating the persona did not finish")
}
