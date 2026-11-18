//! `openvtc script` — drive the real client without a terminal (feature `scripted`).
//!
//! This is the TUI with its screen replaced by a script. The state handler, its
//! runtime loop, the VTA session, the mediator connection and every inbound
//! handler are the production ones (`StateHandler::main_loop`). Where the
//! ratatui UI turns a key press into an [`Action`], a script sends the same
//! action, and where a person reads the screen, the script waits on the same
//! [`State`]. Nothing here builds a message or touches a key: it only says what
//! a person at the keyboard would say.
//!
//! It exists so the vetting flows can be run end to end against a live stack,
//! repeatably, for review (`infra/scripts/vetting-run.sh`). It is a research
//! harness, built only with the `scripted` feature, never by default.
//!
//! Several people are several processes, one profile each. They coordinate
//! through files in a shared directory (`--exchange`): a vetter writes the
//! ticket it issued, an applicant waits for it. That is the out-of-band channel
//! the design leaves to people (a ticket is handed over in person or by chat).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Arg, ArgMatches, Command};
use tokio::sync::{mpsc, watch};

use crate::state_handler::actions::{Action, VettingAction as V};
use crate::state_handler::main_page::menu::MainMenu;
use crate::state_handler::state::State;
use crate::state_handler::{DeferredLoad, StartingMode, StateHandler};

/// The `script` subcommand.
pub fn command() -> Command {
    let exchange = Arg::new("exchange")
        .long("exchange")
        .required(true)
        .help("Directory shared by the people in the run: tickets and progress files");
    let community = Arg::new("community")
        .long("community")
        .required(true)
        .help("The community's DID");
    let timeout = Arg::new("timeout")
        .long("timeout")
        .default_value("600")
        .value_parser(clap::value_parser!(u64))
        .help("Seconds any one step may take");
    Command::new("script")
        .about("Drive the client from a script instead of the TUI (research harness)")
        .subcommand_required(true)
        .subcommand(
            Command::new("observe")
                .about("Run the client and print the vetting state and activity log")
                .arg(
                    Arg::new("seconds")
                        .long("seconds")
                        .default_value("30")
                        .value_parser(clap::value_parser!(u64)),
                ),
        )
        .subcommand(
            Command::new("vetter")
                .about("Issue a ticket, then run each session that arrives on it and attest")
                .arg(exchange.clone())
                .arg(community.clone())
                .arg(timeout.clone())
                .arg(
                    Arg::new("name")
                        .long("name")
                        .required(true)
                        .help("This vetter's name in the exchange directory"),
                )
                .arg(
                    Arg::new("sessions")
                        .long("sessions")
                        .default_value("1")
                        .value_parser(clap::value_parser!(usize))
                        .help("How many applicants to attest before stopping"),
                )
                .arg(
                    Arg::new("hidden")
                        .long("hidden")
                        .action(clap::ArgAction::SetTrue)
                        .help("The community runs hidden vetting: draw tokens first"),
                ),
        )
        .subcommand(
            Command::new("applicant")
                .about("Apply, request each vetter's ticket, send the cards, and join")
                .arg(exchange)
                .arg(community)
                .arg(timeout)
                .arg(
                    Arg::new("vetters")
                        .long("vetters")
                        .required(true)
                        .num_args(1..)
                        .help("The vetters (names in the exchange directory) to ask"),
                )
                .arg(
                    Arg::new("hidden")
                        .long("hidden")
                        .action(clap::ArgAction::SetTrue)
                        .help("Apply on the community's hidden (PCS) vetting path"),
                ),
        )
        .subcommand(
            Command::new("join")
                .about("Join a community whose vetting requirements this applicant already meets")
                .arg(
                    Arg::new("community")
                        .long("community")
                        .required(true)
                        .help("The community's DID"),
                )
                .arg(
                    Arg::new("timeout")
                        .long("timeout")
                        .default_value("600")
                        .value_parser(clap::value_parser!(u64)),
                ),
        )
}

/// Run a `script` subcommand on a loaded profile.
pub async fn run(args: &ArgMatches, profile: &str, deferred: DeferredLoad) -> Result<()> {
    let (terminator, interrupt_rx) = crate::create_termination();
    let (state, state_rx) =
        StateHandler::new(profile, StartingMode::MainPageDeferred(Box::new(deferred)));
    let (action_tx, action_rx) = mpsc::unbounded_channel();
    // The state handler's loop is not `Send`, so it runs on this task beside
    // the script, as it runs beside the UI in `main` (`run_session`).
    let handler = state.main_loop(terminator.clone(), action_rx, interrupt_rx.resubscribe());

    let mut stop = terminator;
    let script = async move {
        let mut driver = Driver::new(action_tx, state_rx);
        let result = match args.subcommand() {
            Some(("observe", a)) => {
                let seconds = *a.get_one::<u64>("seconds").expect("defaulted");
                driver.observe(Duration::from_secs(seconds)).await
            }
            Some(("vetter", a)) => roles::vetter(&mut driver, a).await,
            Some(("applicant", a)) => roles::applicant(&mut driver, a).await,
            Some(("join", a)) => roles::join_only(&mut driver, a).await,
            _ => Err(anyhow!("unknown script")),
        };
        driver.flush_log();
        // Saves are coalesced (`save_coalesce`): give the last one a moment to
        // land before asking the loop to stop, as a person quitting would.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let _ = stop.terminate(crate::Interrupted::UserInt);
        result
    };
    let (handler_result, result) = tokio::join!(handler, script);
    if let Err(e) = handler_result {
        eprintln!("client loop ended with an error: {e}");
    }
    result
}

/// What a script does in place of a person at the keyboard.
pub(crate) struct Driver {
    tx: mpsc::UnboundedSender<Action>,
    rx: watch::Receiver<Arc<State>>,
    /// Activity-log entries already printed (the log is newest-first, bounded).
    seen: std::collections::HashSet<String>,
    pub(crate) step_timeout: Duration,
}

impl Driver {
    fn new(tx: mpsc::UnboundedSender<Action>, rx: watch::Receiver<Arc<State>>) -> Self {
        Self {
            tx,
            rx,
            seen: Default::default(),
            step_timeout: Duration::from_secs(600),
        }
    }

    /// A step heading, as a person would narrate it.
    pub(crate) fn say(&self, what: impl AsRef<str>) {
        println!("\n== {}", what.as_ref());
    }

    /// Press a key: send the action the TUI would send for it.
    pub(crate) fn send(&self, action: Action) -> Result<()> {
        self.tx
            .send(action)
            .map_err(|_| anyhow!("the client stopped (state handler gone)"))
    }

    pub(crate) fn vetting(&self, action: V) -> Result<()> {
        self.send(Action::Vetting(action))
    }

    /// The state as the screen would show it now.
    pub(crate) fn state(&self) -> Arc<State> {
        self.rx.borrow().clone()
    }

    /// Print activity-log entries not printed yet, oldest first.
    pub(crate) fn flush_log(&mut self) {
        let state = self.state();
        let mut fresh: Vec<_> = state
            .main_page
            .activity_log
            .iter()
            .filter(|e| self.seen.insert(e.summary.clone()))
            .collect();
        fresh.reverse();
        for entry in fresh {
            println!("   | {}", entry.summary);
            if std::env::var_os("SCRIPT_LOG_DETAIL").is_some()
                && let Some(detail) = &entry.detail
            {
                for line in detail.lines() {
                    println!("   |     {line}");
                }
            }
        }
    }

    /// Wait until `done` holds of the state, for at most the step timeout. The
    /// activity log is streamed meanwhile; a vetting status message that is an
    /// error ends the wait, since a person would stop there too.
    pub(crate) async fn wait_for<T>(
        &mut self,
        what: &str,
        mut done: impl FnMut(&State) -> Option<T>,
    ) -> Result<T> {
        let deadline = Instant::now() + self.step_timeout;
        let mut last_status: Option<String> = None;
        loop {
            self.flush_log();
            let state = self.state();
            if let Some(found) = done(&state) {
                return Ok(found);
            }
            if let Some(status) = &state.main_page.content_panel.vetting.status_message {
                let text = status.to_string();
                if last_status.as_deref() != Some(text.as_str()) {
                    println!("   > {text}");
                    last_status = Some(text);
                }
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                bail!(
                    "timed out waiting for: {what}\n--- vetting state ---\n{:#?}",
                    state.main_page.content_panel.vetting
                );
            }
            // Wake on a state change, or poll every second (the log and
            // background jobs move without one).
            let _ = tokio::time::timeout(left.min(Duration::from_secs(1)), self.rx.changed()).await;
        }
    }

    /// Run with no script: print what happens for `seconds`, then the vetting state.
    async fn observe(&mut self, seconds: Duration) -> Result<()> {
        self.send(Action::MainMenuSelected(MainMenu::Vetting))?;
        let end = Instant::now() + seconds;
        while Instant::now() < end {
            self.flush_log();
            let _ = tokio::time::timeout(Duration::from_secs(1), self.rx.changed()).await;
        }
        println!("{:#?}", self.state().main_page.content_panel.vetting);
        Ok(())
    }
}

/// The out-of-band channel between the people in a run.
pub(crate) struct Exchange(PathBuf);

impl Exchange {
    pub(crate) fn new(dir: &str) -> Result<Self> {
        std::fs::create_dir_all(dir).with_context(|| format!("create {dir}"))?;
        Ok(Self(PathBuf::from(dir)))
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Hand something over (atomically, so a reader never sees half of it).
    pub(crate) fn put(&self, name: &str, value: &str) -> Result<()> {
        let tmp = self.path(&format!(".{name}.tmp"));
        std::fs::write(&tmp, value)?;
        std::fs::rename(&tmp, self.path(name))?;
        Ok(())
    }

    /// Wait for something to be handed over.
    pub(crate) async fn take(&self, name: &str, timeout: Duration) -> Result<String> {
        let deadline = Instant::now() + timeout;
        let path = self.path(name);
        loop {
            if let Ok(value) = std::fs::read_to_string(&path) {
                return Ok(value.trim().to_string());
            }
            if Instant::now() >= deadline {
                bail!("timed out waiting for {}", path.display());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

mod face;
mod join;
mod persona;
mod roles;
