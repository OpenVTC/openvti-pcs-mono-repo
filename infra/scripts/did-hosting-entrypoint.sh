#!/bin/sh
# did-hosting-daemon container entrypoint: self-managed setup on first start
# (empty volume), then run the daemon. Offline maintenance (add-acl, ...) is
# done by bootstrap.sh with this service stopped.
set -eu
cd /var/lib/did-hosting
if [ ! -f config.toml ]; then
    echo "did-hosting: first start, self-managed setup (did-hosting-daemon setup --from)"
    /usr/local/bin/did-hosting-daemon setup --from /config/did-hosting-daemon.toml --non-interactive
fi
exec /usr/local/bin/did-hosting-daemon -c config.toml
