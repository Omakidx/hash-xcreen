#!/usr/bin/env bash
# Build-on-server path: launch a base image and apply a recipe, timing each phase.
# Usage: build.sh <recipe.toml> <container> <cpu> <mem> [--addon addons/docker.toml]...
# Needs `incus` access and the hx-recipe binary (cd runner && cargo build --release).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
recipe=$1 name=$2 cpu=$3 mem=$4; shift 4
bin=${HX_RECIPE:-$here/runner/target/release/hx-recipe}
base=$(grep -h '^base_image' "$here/fragments/distro-$(basename "$recipe" | sed -E 's/-xfce.*//').toml" | cut -d'"' -f2)
echo "loadavg_start $(cut -d' ' -f1-3 /proc/loadavg)"
t0=$(date +%s.%N)
# INCUS_LAUNCH_ARGS: extra `incus launch` arguments, e.g. "-c raw.apparmor=signal," (Debian 13 on Ubuntu 26.04, see the S3 report)
# shellcheck disable=SC2086
incus launch --quiet "$base" "$name" -c limits.cpu="$cpu" -c limits.memory="$mem" ${INCUS_LAUNCH_ARGS:-}
t1=$(date +%s.%N)
echo "LAUNCH base=$base $(echo "$t1 - $t0" | bc)s (includes image download if not cached)"
"$bin" apply "$recipe" "$name" "$@"
t2=$(date +%s.%N)
echo "TOTAL_BUILD_INCL_LAUNCH $(echo "$t2 - $t0" | bc)s"
echo "loadavg_end $(cut -d' ' -f1-3 /proc/loadavg)"
