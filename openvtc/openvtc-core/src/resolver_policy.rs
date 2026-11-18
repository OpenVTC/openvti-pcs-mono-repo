//! The host policy of every DID resolver and TDK instance OpenVTC builds.
//!
//! Resolvers refuse DIDs hosted on private or loopback addresses by default
//! (an SSRF guard). A local stack — every service on `localhost` — needs that
//! lifted, and the VTI services lift it with `VTA_ALLOW_PRIVATE_ENDPOINTS=1`
//! (`vta_sdk::resolver`). OpenVTC honours the same switch, from here, so the
//! client and the services it talks to always agree on what resolves.
//!
//! The same switch lets this client fetch a community's status lists and
//! manifest over plain http on such a stack (`vetting::status`,
//! `join::sequence`).
//!
//! Unset (the default), nothing changes: public hosts only, https only.

use affinidi_did_resolver_cache_sdk::config::DIDCacheConfig;
use affinidi_tdk::common::config::{TDKConfig, TDKConfigBuilder};

/// Whether the operator opted in to private/loopback DID hosts.
#[must_use]
pub fn allow_private_hosts() -> bool {
    vta_sdk::resolver::allow_private_did_hosts()
}

/// The policy for this client's own HTTP probes of community endpoints
/// (reading a manifest): private and plain-http endpoints only under the opt-in.
#[must_use]
pub fn probe_policy() -> crate::health::ProbePolicy {
    if allow_private_hosts() {
        crate::health::ProbePolicy::AllowPrivate
    } else {
        crate::health::ProbePolicy::PublicOnly
    }
}

/// A resolver configuration carrying the host policy.
#[must_use]
pub fn did_cache_config() -> DIDCacheConfig {
    vta_sdk::resolver::build_did_cache_config(None)
}

/// A TDK configuration builder (environment file not loaded) whose resolver
/// carries the host policy.
#[must_use]
pub fn tdk_config_builder() -> TDKConfigBuilder {
    TDKConfig::builder()
        .with_load_environment(false)
        .with_did_resolver_config(did_cache_config())
}
