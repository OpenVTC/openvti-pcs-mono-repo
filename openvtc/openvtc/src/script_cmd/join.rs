//! Joining once the application meets the community's requirements: the join
//! flow's vetting page, `j` (present the statements), and the verdict.

use anyhow::Result;

use super::Driver;
use crate::state_handler::actions::Action;
use crate::state_handler::join::JoinPage;

pub(super) async fn finish_join(d: &mut Driver, community: &str) -> Result<()> {
    d.wait_for("the join flow's vetting page", |s| {
        matches!(s.join.page, JoinPage::Vetting).then_some(())
    })
    .await?;
    d.send(Action::JoinVettingJoin)?;
    let mut printed = 0;
    d.wait_for("the community's verdict (admission)", |s| {
        for m in s.join.messages.iter().skip(printed) {
            println!("   join: {m:?}");
        }
        printed = s.join.messages.len();
        // The main page scopes itself to an active membership as soon as one
        // exists; an applicant with no other community has this one exactly
        // when it has been admitted.
        s.selected_community
            .as_ref()
            .is_some_and(|(vtc, _)| vtc == community)
            .then_some(())
    })
    .await
}
