#!/bin/bash
#
# Regenerate the embedded CloudModel fallback files for edamame_foundation.
#
# IMPORTANT: every fallback in this directory is OBFUSCATED via
# tools/encode_cloud_fallback.py (gzip + XOR). The published JSON in
# `../threatmodels/` stays in plain form -- only the fallback we ship in
# the helper binary's rodata gets obfuscated. The reason is Microsoft
# Defender's Stealc/Stealga ML model: threat_metrics_windows.rs in
# particular contains a full credential-stealer reconnaissance corpus
# (password manager extension IDs, browser User Data paths, registry
# probes), and embedded as a raw string literal that whole corpus shows
# up in `strings(1)` against the signed binary -- which trips
# `Trojan:Win32/Stealga.HAK!MTB`.
#
# The runtime decoder lives in `src/cloud_model_fallback.rs`.

set -e

ENCODER=./tools/encode_cloud_fallback.py

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required to run the obfuscation encoder" >&2
    exit 1
fi
if [ ! -x "$ENCODER" ]; then
    chmod +x "$ENCODER" || true
fi

current_branch() {
    local b
    b=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo dev)
    if [ "$b" != "main" ] && [ "$b" != "dev" ]; then
        b=dev
    fi
    echo "$b"
}

# Fetch a single source JSON (local copy under ../threatmodels/ if --local,
# otherwise raw.githubusercontent.com on the current branch) into a temp
# file. Aborts with a clear message if the result is empty.
fetch_source_json() {
    local source_filename=$1
    local is_local=$2
    local out=$3

    if [ "$is_local" = true ]; then
        echo "  Using local ../threatmodels/${source_filename}"
        cp "../threatmodels/${source_filename}" "$out"
    else
        local branch
        branch=$(current_branch)
        echo "  Fetching ${source_filename} from threatmodels@${branch}"
        wget --no-cache -qO "$out" "https://raw.githubusercontent.com/edamametechnologies/threatmodels/${branch}/${source_filename}"
    fi

    if [ ! -s "$out" ]; then
        echo "ERROR: empty or missing ${source_filename} (target $out) -- aborting" >&2
        return 1
    fi
}

update_obfuscated_fallback() {
    local source_filename=$1
    local target_rs=$2
    local static_name=$3
    local comment=$4
    local is_local=$5

    echo "Updating ${static_name} (obfuscated CloudModel fallback)"

    local tmp_json
    tmp_json=$(mktemp -t edamame_threatmodel.XXXXXX.json)
    trap 'rm -f "$tmp_json"' RETURN

    fetch_source_json "$source_filename" "$is_local" "$tmp_json"

    python3 "$ENCODER" \
        "$tmp_json" \
        "$target_rs" \
        "$static_name" \
        "$comment"
}

update_threat_metrics() {
    local os=$1
    local is_local=${2:-false}
    local os_lower
    os_lower=$(echo "$os" | tr '[:upper:]' '[:lower:]')
    local os_upper
    os_upper=$(echo "$os" | tr '[:lower:]' '[:upper:]')

    update_obfuscated_fallback \
        "threatmodel-${os}.json" \
        "./src/threat_metrics_${os_lower}.rs" \
        "THREAT_METRICS_${os_upper}" \
        "Built in default ${os} threat model (obfuscated)" \
        "$is_local"
}

update_cve_detection_params_db() {
    local is_local=${1:-false}
    update_obfuscated_fallback \
        "cve-detection-params-db.json" \
        "./src/cve_detection_params_db.rs" \
        "CVE_DETECTION_PARAMS_DB" \
        "Built in default CVE detection params db (obfuscated)" \
        "$is_local"
}

# Define the array of target operating systems.
targets=("macOS" "Linux" "Windows" "iOS" "Android")

# Parse command line arguments.
USE_LOCAL=false
SPECIFIC_OS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --local)
            USE_LOCAL=true
            shift
            ;;
        *)
            SPECIFIC_OS=$1
            shift
            ;;
    esac
done

if [ -n "$SPECIFIC_OS" ]; then
    update_threat_metrics "$SPECIFIC_OS" "$USE_LOCAL"
else
    for os in "${targets[@]}"; do
        update_threat_metrics "$os" "$USE_LOCAL"
    done
    update_cve_detection_params_db "$USE_LOCAL"
fi
