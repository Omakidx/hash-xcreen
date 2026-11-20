#!/usr/bin/env bash
# Prebuilt-image path: publish a built container as an image, export it to files, then time
# import + launch + post-steps (security updates, user/password) from those files.
# Usage: prebuilt.sh <built-container> <recipe.toml> <outdir> <cpu> <mem> [compression=default]
# Prints key=value lines. Estimates of download time are computed from the file size.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
src=$1 recipe=$2 out=$3 cpu=$4 mem=$5 comp=${6:-default}
bin=${HX_RECIPE:-$here/runner/target/release/hx-recipe}
alias=s3-img-$src
new=s3-pre-${src#s3-}
mkdir -p "$out"
now() { date +%s.%N; }
span() { echo "scale=1; ($2 - $1)/1" | bc; }

echo "loadavg_start $(cut -d' ' -f1-3 /proc/loadavg)"
incus stop "$src" 2>/dev/null || true
t=$(now)
if [ "$comp" = default ]; then incus publish "$src" --alias "$alias" >/dev/null; else incus publish "$src" --alias "$alias" --compression "$comp" >/dev/null; fi
echo "publish_s=$(span "$t" "$(now)")"
echo "image_compression=$comp (server default: $(incus config get images.compression_algorithm || true))"

t=$(now)
incus image export "$alias" "$out/$alias" >/dev/null
echo "export_s=$(span "$t" "$(now)")"
ls -l "$out" | awk 'NR>1{print "export_file " $9 " " $5 " bytes"}'
bytes=$(cat "$out"/"$alias"* | wc -c)
echo "image_bytes=$bytes image_mib=$((bytes/1048576))"
for mbps in 100 1000; do
  echo "download_estimate_${mbps}mbps_s=$(echo "scale=1; $bytes*8/($mbps*1000000)" | bc)  (ESTIMATE, size / line rate, no protocol overhead)"
done

incus image delete "$alias"
t0=$(now)
# --alias must be given after the files for `image import`
incus image import --quiet "$out"/"$alias"* --alias "$alias" >/dev/null
t1=$(now); echo "import_s=$(span "$t0" "$t1")"
incus launch --quiet "$alias" "$new" -c limits.cpu="$cpu" -c limits.memory="$mem" >/dev/null
t2=$(now); echo "launch_s=$(span "$t1" "$t2")"
HX_PASSWORD=${HX_PASSWORD:-s3-test-password} "$bin" post "$recipe" "$new" 2>&1 | grep -E 'STAGE|TOTAL|error' || true
t3=$(now)
echo "post_steps_s=$(span "$t2" "$t3")"
echo "PREBUILT_LOCAL_TOTAL_s=$(span "$t0" "$t3")  (import+launch+post, excludes download)"
echo "loadavg_end $(cut -d' ' -f1-3 /proc/loadavg)"
