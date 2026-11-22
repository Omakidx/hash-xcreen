#!/bin/sh
# The performance suite: criterion microbenchmarks, the macro run (the LAN end-to-end flow
# repeated), and the comparison with perf/baseline.json.
#
#   perf/run.sh                       run everything, check the gates (a loaded machine is told so)
#   perf/run.sh --mode regression     also compare with the baseline recorded on the runner
#   perf/run.sh --strict              enforce timing gates even if the host is busy
#   perf/run.sh --update [--reference]  record the numbers as the new baseline (no checks)
#   perf/run.sh --micro-only | --macro-only
#
# Environment: HX_PERF_RUNS (macro repetitions, default 5), HX_PERF_RES (default 1920x1080),
# HX_PERF_BENCH_ARGS (extra criterion arguments),
# HX_PERF_STRICT=1 (same as --strict). Needs the system libraries of docs/testing.md, Xvfb,
# cargo-nextest, python3, iproute2 (ip, tc), ping, util-linux (unshare, nsenter) and permission
# for unprivileged user namespaces. Never needs root.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")
cd "$root"

micro=1
macro=1
check_args=""
for a in "$@"; do
    case "$a" in
        --micro-only) macro=0 ;;
        --macro-only) micro=0 ;;
        --strict) check_args="$check_args --strict"; HX_PERF_STRICT=1; export HX_PERF_STRICT ;;
        *) check_args="$check_args $a" ;;
    esac
done
if [ "${HX_PERF_STRICT:-}" = 1 ]; then
    case "$check_args" in *--strict*) ;; *) check_args="$check_args --strict" ;; esac
fi

HX_REQUIRE_XVFB=1
export HX_REQUIRE_XVFB

if [ "$micro" = 1 ]; then
    rm -rf target/criterion
    # HX_PERF_BENCH_ARGS: extra criterion arguments, e.g. "--warm-up-time 1 --measurement-time 2"
    # for a quick look on a development machine (the runner uses the defaults).
    # shellcheck disable=SC2086 # flags, split on purpose
    # The bench targets are named: the crates' own unit-test harnesses would reject criterion's
    # arguments.
    cargo bench --locked -p hx-proto -p hx-ipc -p hx-codec -p hx-session \
        --bench proto --bench link --bench handoff --bench capture_to_encode \
        -- ${HX_PERF_BENCH_ARGS:-}
fi

if [ "$macro" = 1 ]; then
    rm -f target/tmp/perf-macro.json
    HX_PERF=1
    HX_PERF_RUNS="${HX_PERF_RUNS:-5}"
    export HX_PERF HX_PERF_RUNS
    cargo nextest run --release --locked -p hx-agent --run-ignored only --test e2e_netem \
        --no-capture --no-tests=fail -E 'test(perf_macro_lan)'
fi

# shellcheck disable=SC2086 # the arguments are flags, split on purpose
exec python3 -I "$here/check.py" $check_args
