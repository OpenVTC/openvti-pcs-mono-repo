//! OPENVTC-RESEARCH LOCAL PATCH (see infra/PROVENANCE.md in openvtc-research).
//!
//! The local research stack publishes every `did:webvh` on `localhost`, which
//! the DID resolver's default `HostPolicy::PublicOnly` refuses before any
//! request is made. Setting `DID_HOSTING_ALLOW_PRIVATE_DID_HOSTS=1` makes the
//! resolvers this service builds use `HostPolicy::AllowPrivate` instead (and
//! fetch `localhost` DIDs over plain http). Unset, behaviour is unchanged.
//! Never set it in a deployment.

use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
use affinidi_did_resolver_cache_sdk::network_resolvers::HostPolicy as CacheHostPolicy;

/// Environment switch for the local stack.
pub const ALLOW_PRIVATE_ENV: &str = "DID_HOSTING_ALLOW_PRIVATE_DID_HOSTS";

/// Whether the operator opted into resolving loopback/private DID hosts.
pub fn allow_private_did_hosts() -> bool {
    std::env::var(ALLOW_PRIVATE_ENV)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// `DIDCacheConfigBuilder::default()`, with the host policy the switch selects.
pub fn cache_config_builder() -> DIDCacheConfigBuilder {
    let builder = DIDCacheConfigBuilder::default();
    if allow_private_did_hosts() {
        builder.with_host_policy(CacheHostPolicy::AllowPrivate)
    } else {
        builder
    }
}
