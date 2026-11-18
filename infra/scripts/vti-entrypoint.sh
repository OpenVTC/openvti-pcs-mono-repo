#!/bin/sh
# VTA / VTC container entrypoint.
#
#   vti-entrypoint.sh vta   ->  vta --config /var/lib/vta/config.toml
#   vti-entrypoint.sh vtc   ->  vtc --config /var/lib/vtc/config.toml
#
# Provisioning is done by infra/bootstrap.sh with offline commands that need
# exclusive access to the store, so the daemon does not start until bootstrap
# has written the `.bootstrapped` marker into the service's volume. Until then
# the container idles (and reports unhealthy) instead of crash-looping.
set -eu
svc="${1:?usage: vti-entrypoint.sh vta|vtc}"
dir="/var/lib/${svc}"
if [ ! -f "${dir}/.bootstrapped" ]; then
    echo "${svc}: not provisioned yet; run infra/bootstrap.sh. Waiting for ${dir}/.bootstrapped ..."
    while [ ! -f "${dir}/.bootstrapped" ]; do sleep 2; done
fi
exec "/usr/local/bin/${svc}" --config "${dir}/config.toml"
