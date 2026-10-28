#!/usr/bin/env bash
# One parallel fuzzing chunk: every target runs its workers for
# SECONDS_PER_CHUNK wall time, then the script waits for all of them.
# Workers of one target share the corpus dir (libFuzzer -reload merges new
# units across workers every second); the seeds dir is a read-only extra
# corpus. Corpus, logs and crash artifacts persist across chunks.
#
# Usage: fuzz/scripts/run-parallel.sh [seconds]
set -u
cd "$(dirname "$0")/.."

SECONDS_PER_CHUNK="${1:-560}"
BIN_DIR="target/x86_64-pc-windows-msvc/release"
mkdir -p artifacts fuzzlog
# Workers leak their per-process host repos (deliberately leaked tempdirs),
# so point the OS temp dir at a dedicated gitignored dir for easy cleanup.
mkdir -p tmp-host
export TEMP="$PWD/tmp-host" TMP="$PWD/tmp-host"

# launch <target> <workers> [extra libfuzzer args...]
launch() {
    local target="$1" workers="$2"
    shift 2
    local bin="$BIN_DIR/$target.exe"
    if [ ! -x "$bin" ]; then
        echo "missing fuzz binary: $bin (run: cargo fuzz build)" >&2
        return 1
    fi
    mkdir -p "corpus/$target" "seeds/$target"
    for i in $(seq 1 "$workers"); do
        "$bin" \
            -max_total_time="$SECONDS_PER_CHUNK" \
            -print_final_stats=1 \
            -rss_limit_mb=2560 \
            -artifact_prefix="artifacts/${target}-w${i}-" \
            "$@" \
            "corpus/${target}" \
            "seeds/${target}" \
            >>"fuzzlog/${target}.log" 2>&1 &
    done
}

launch roundtrip_encrypt_decrypt 6 -max_len=8192
launch decrypt_arbitrary 12 -max_len=131072
launch process_filter_session 10 -max_len=8192
launch salt_cache_parse 4 -max_len=8192

wait
echo "chunk finished: $(date)"
