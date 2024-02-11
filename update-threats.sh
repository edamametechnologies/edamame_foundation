#!/bin/bash

update_threat_metrics() {
    local os=$1
    local os_lower=$(echo $os | tr '[:upper:]' '[:lower:]')
    local os_upper=$(echo $os | tr '[:lower:]' '[:upper:]')

    echo "Updating threat metrics for $os / $os_lower / $os_upper"

    # Delete the file if it exists
    if [ -f "$target" ]; then
        rm "$target"
    fi

    local branch=$(git rev-parse --abbrev-ref HEAD)
    # Only deal with main and dev branches, default to dev
    if [ $branch != "dev" ] && [ $branch != "main" ]; then
      branch=dev
    fi
    local target=./src/threat_metrics_$os_lower.rs
    local header="// Built in default threat model\npub static THREAT_METRICS_$os_upper: &str = r#\""
    local trailer="\"#;"
    # Prevent bash parsing of escape chars
    local body="$(wget --no-cache -qO- https://raw.githubusercontent.com/edamametechnologies/threatmodels/$branch/threatmodel-$os.json)"
    # Interpret escape chars
    echo -n -e "$header" > "$target"
    # Preserve escape chars
    echo -n "$body" >> "$target"
    # Interpret escape chars
    echo -e $trailer >> "$target"
}

update_lanscan_port_vulns () {
    local target=./src/lanscan_port_vulns_db.rs
    local header="// Built in default port vulns db\npub static PORT_VULNS: &str = r#\""
    local trailer="\"#;"

    echo "Updating lanscan port vulns db"

    # Delete the file if it exists
    if [ -f "$target" ]; then
        rm "$target"
    fi

    local branch=$(git rev-parse --abbrev-ref HEAD)
    # Only deal with main and dev branches, default to dev
    if [ $branch != "dev" ] && [ $branch != "main" ]; then
      branch=dev
    fi
    # Prevent bash parsing of escape chars
    local body="$(wget --no-cache -qO- https://raw.githubusercontent.com/edamametechnologies/threatmodels/$branch/lanscan-port-vulns-db.json)"
    # Interpret escape chars
    echo -n -e "$header" > "$target"
    # Preserve escape chars
    echo -n "$body" >> "$target"
    # Interpret escape chars
    echo -e $trailer >> "$target"
}

update_lanscan_profiles () {
    local target=./src/lanscan_profiles_db.rs
    local header="// Built in default profile db\npub static DEVICE_PROFILES: &str = r#\""
    local trailer="\"#;"

    echo "Updating lanscan profiles db"

    # Delete the file if it exists
    if [ -f "$target" ]; then
        rm "$target"
    fi
    local branch=$(git rev-parse --abbrev-ref HEAD)
    # Only deal with main and dev branches, default to dev
    if [ $branch != "dev" ] && [ $branch != "main" ]; then
      branch=dev
    fi
    # Prevent bash parsing of escape chars
    local body="$(wget --no-cache -qO- https://raw.githubusercontent.com/edamametechnologies/threatmodels/$branch/lanscan-profiles-db.json)"
    # Interpret escape chars
    echo -n -e "$header" > "$target"
    # Preserve escape chars
    echo -n "$body" >> "$target"
    # Interpret escape chars
    echo -e $trailer >> "$target"
}

# Define the array of target operating systems
targets=("macOS" "Linux" "Windows" "iOS" "Android")

# Check if an argument is given
if [ $# -eq 0 ]; then
    # Loop through all targets
    for os in "${targets[@]}"; do
        update_threat_metrics $os
    done
    update_lanscan_profiles
    update_lanscan_port_vulns
else
    # If an argument is provided, just use that
    update_threat_metrics $1
    update_lanscan_profiles
    update_lanscan_port_vulns
fi
