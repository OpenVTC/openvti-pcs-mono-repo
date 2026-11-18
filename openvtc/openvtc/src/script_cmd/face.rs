//! The new-face form (`VettingMode::NewFace`): name the face, type a value for
//! each required claim the pool has nothing for, then Enter until it is made.

use std::time::Duration;

use anyhow::{Result, bail};

use super::Driver;
use crate::state_handler::actions::VettingAction as V;
use crate::state_handler::main_page::content::{NewFaceFocus, VettingMode};

/// The values typed for claims a community may require.
fn value_for(claim_type: &str) -> String {
    match claim_type {
        "name.legal" => std::env::var("SCRIPT_LEGAL_NAME").unwrap_or_else(|_| "Research Applicant".into()),
        other => format!("research value for {other}"),
    }
}

pub(super) async fn fill_new_face(d: &mut Driver) -> Result<()> {
    for _ in 0..30 {
        let form = match &d.state().main_page.content_panel.vetting.mode {
            VettingMode::NewFace(form) => (**form).clone(),
            _ => return Ok(()),
        };
        if form.saving.is_some() {
            tokio::time::sleep(Duration::from_millis(300)).await;
            continue;
        }
        if let Some(error) = &form.error {
            println!("   new face: {error}");
        }
        match form.focus {
            NewFaceFocus::Name if form.name.trim().is_empty() => {
                d.vetting(V::Input("Vetting".into()))?;
            }
            NewFaceFocus::Asked(_) => {
                if let Some(text) = form.text()
                    && text.trim().is_empty()
                {
                    let claim = form
                        .asked()
                        .into_iter()
                        .map(|(c, _)| c.to_string())
                        .find(|c| form.drafts.get(c).is_none_or(|v| v.is_empty()))
                        .unwrap_or_default();
                    d.vetting(V::Input(value_for(&claim)))?;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
            _ => {}
        }
        d.vetting(V::Submit)?;
        tokio::time::sleep(Duration::from_millis(700)).await;
    }
    bail!("the new-face form did not finish")
}
