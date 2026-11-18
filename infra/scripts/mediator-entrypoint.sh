#!/bin/sh
# Mediator container entrypoint: generate an identity on first start (empty
# config volume), then run the mediator. Mirrors the upstream quickstart's
# one-shot `setup` service, folded into the same container.
set -eu
cd /etc/mediator
if [ ! -f conf/mediator.toml ]; then
    echo "mediator: first start, generating a fresh identity (mediator-setup --from)"
    /usr/local/bin/mediator-setup --from /config/mediator-build.toml
fi
exec /usr/local/bin/mediator -c conf/mediator.toml
