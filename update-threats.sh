#!/bin/bash

update_threat_metrics() {
    local os=$1
    local is_local=${2:-false}
    local os_lower=$(echo $os | tr '[:upper:]' '[:lower:]')
    local os_upper=$(echo $os | tr '[:lower:]' '[:upper:]')

    echo "Updating threat metrics for $os / $os_lower / $os_upper"

    local target=./src/threat_metrics_$os_lower.rs
    local header="// Built in default threat model\npub static THREAT_METRICS_$os_upper: &str = r#\""
    local trailer="\"#;"

    # Delete the file if it exists
    if [ -f "$target" ]; then
        rm "$target"
    fi

    if [ "$is_local" = true ]; then
        echo "Using local threat model file"
        # Prevent bash parsing of escape chars
        local body="$(cat ../threatmodels/threatmodel-$os.json)"
    else
        echo "Fetching threat model from GitHub"
        local branch=$(git rev-parse --abbrev-ref HEAD)
        # Prevent bash parsing of escape chars
        local body="$(wget --no-cache -qO- https://raw.githubusercontent.com/edamametechnologies/threatmodels/$branch/threatmodel-$os.json)"
        # If body is empty try again with the dev branch
        if [ -z "$body" ]; then
            echo "Failed to fetch threat model for $os from $branch, trying dev branch"
            body="$(wget --no-cache -qO- https://raw.githubusercontent.com/edamametechnologies/threatmodels/dev/threatmodel-$os.json)"
        fi
    fi

    # Interpret escape chars
    echo -n -e "$header" > "$target"
    # Preserve escape chars
    echo -n "$body" >> "$target"
    # Interpret escape chars
    echo -e $trailer >> "$target"
}

update_lanscan_port_vulns () {
    local is_local=${1:-false}
    local target=./src/lanscan_port_vulns_db.rs
    # We need to use 4 # in order to deal with the mess of escape chars found in the CVE descriptions
    local header="// Built in default port vulns db\npub static PORT_VULNS: &str = r####\""
    local trailer="\"####;"

    echo "Updating lanscan port vulns db"

    # Delete the file if it exists
    if [ -f "$target" ]; then
        rm "$target"
    fi

    if [ "$is_local" = true ]; then
        echo "Using local port vulns db file"
        local body="$(cat ../threatmodels/lanscan-port-vulns-db.json)"
    else
        echo "Fetching port vulns db from GitHub"
        local branch=$(git rev-parse --abbrev-ref HEAD)
        # Only deal with main and dev branches, default to dev
        if [ $branch != "dev" ] && [ $branch != "main" ]; then
          branch=dev
        fi
        # Prevent bash parsing of escape chars
        local body="$(wget --no-cache -qO- https://raw.githubusercontent.com/edamametechnologies/threatmodels/$branch/lanscan-port-vulns-db.json)"
    fi

    # Interpret escape chars
    echo -n -e "$header" > "$target"
    # Preserve escape chars
    echo -n "$body" >> "$target"
    # Interpret escape chars
    echo -e $trailer >> "$target"
}

update_lanscan_vendor_vulns () {
    local is_local=${1:-false}
    local target=./src/lanscan_vendor_vulns_db.rs
    # We need to use 4 # in order to deal with the mess of escape chars found in the CVE descriptions
    local header="// Built in default vendor vulns db\npub static VENDOR_VULNS: &str = r####\""
    local trailer="\"####;"

    echo "Updating lanscan vendor vulns db"

    # Delete the file if it exists
    if [ -f "$target" ]; then
        rm "$target"
    fi

    if [ "$is_local" = true ]; then
        echo "Using local vendor vulns db file"
        local body="$(cat ../threatmodels/lanscan-vendor-vulns-db.json)"
    else
        echo "Fetching vendor vulns db from GitHub"
        local branch=$(git rev-parse --abbrev-ref HEAD)
        # Only deal with main and dev branches, default to dev
        if [ $branch != "dev" ] && [ $branch != "main" ]; then
          branch=dev
        fi
        # Prevent bash parsing of escape chars
        local body="$(wget --no-cache -qO- https://raw.githubusercontent.com/edamametechnologies/threatmodels/$branch/lanscan-vendor-vulns-db.json)"
    fi

    # Interpret escape chars
    echo -n -e "$header" > "$target"
    # Preserve escape chars
    echo -n "$body" >> "$target"
    # Interpret escape chars
    echo -e $trailer >> "$target"
}

update_lanscan_profiles () {
    local is_local=${1:-false}
    local target=./src/lanscan_profiles_db.rs
    local header="// Built in default profile db\npub static DEVICE_PROFILES: &str = r#\""
    local trailer="\"#;"

    echo "Updating lanscan profiles db"

    # Delete the file if it exists
    if [ -f "$target" ]; then
        rm "$target"
    fi

    if [ "$is_local" = true ]; then
        echo "Using local profiles db file"
        local body="$(cat ../threatmodels/lanscan-profiles-db.json)"
    else
        echo "Fetching profiles db from GitHub"
        local branch=$(git rev-parse --abbrev-ref HEAD)
        # Only deal with main and dev branches, default to dev
        if [ $branch != "dev" ] && [ $branch != "main" ]; then
          branch=dev
        fi
        # Prevent bash parsing of escape chars
        local body="$(wget --no-cache -qO- https://raw.githubusercontent.com/edamametechnologies/threatmodels/$branch/lanscan-profiles-db.json)"
    fi

    # Interpret escape chars
    echo -n -e "$header" > "$target"
    # Preserve escape chars
    echo -n "$body" >> "$target"
    # Interpret escape chars
    echo -e $trailer >> "$target"
}

update_whitelists_db() {
    local is_local=${1:-false}
    local target=./src/whitelists_db.rs
    local header="// Built in default whitelists db\npub static WHITELISTS: &str = r#\""
    local trailer="\"#;"

    echo "Updating whitelists db"

    # Delete the file if it exists
    if [ -f "$target" ]; then
        rm "$target"
    fi

    if [ "$is_local" = true ]; then
        echo "Using local whitelists db file"
        local body="$(cat ../threatmodels/whitelists-db.json)"
    else
        echo "Fetching whitelists db from GitHub"
        local branch=$(git rev-parse --abbrev-ref HEAD)
        # Only deal with main and dev branches, default to dev
        if [ $branch != "dev" ] && [ $branch != "main" ]; then
          branch=dev
        fi
        # Prevent bash parsing of escape chars
        local body="$(wget --no-cache -qO- https://raw.githubusercontent.com/edamametechnologies/threatmodels/$branch/whitelists-db.json)"
    fi

    # Interpret escape chars
    echo -n -e "$header" > "$target"
    # Preserve escape chars
    echo -n "$body" >> "$target"
    # Interpret escape chars
    echo -e $trailer >> "$target"
}

# Define the array of target operating systems
targets=("macOS" "Linux" "Windows" "iOS" "Android")

# Parse command line arguments
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

# Check if a specific OS is given
if [ -n "$SPECIFIC_OS" ]; then
    update_threat_metrics $SPECIFIC_OS $USE_LOCAL
    update_lanscan_profiles $USE_LOCAL
    update_lanscan_port_vulns $USE_LOCAL
    update_lanscan_vendor_vulns $USE_LOCAL
    update_whitelists_db $USE_LOCAL
else
    # Loop through all targets
    for os in "${targets[@]}"; do
        update_threat_metrics $os $USE_LOCAL
    done
    update_lanscan_profiles $USE_LOCAL
    update_lanscan_port_vulns $USE_LOCAL
    update_lanscan_vendor_vulns $USE_LOCAL
    update_whitelists_db $USE_LOCAL
fi