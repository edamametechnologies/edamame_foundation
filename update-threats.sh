#!/bin/bash

update_threat_metrics() {
    local os=$1
    local os_lower=$(echo $os | tr '[:upper:]' '[:lower:]')
    local os_upper=$(echo $os | tr '[:lower:]' '[:upper:]')

    echo "Updating threat metrics for $os / $os_lower / $os_upper"

    local branch=$(git rev-parse --abbrev-ref HEAD)
    # Only deal with main and dev branches, default to dev
    if [ $branch != "dev" ] && [ $branch != "main" ]; then
      branch=dev
    fi
    local target=./src/threat_metrics_$os_lower.rs
    local header="// Built in default threat model\npub static THREAT_METRICS_$os_upper: &str = r#\""
    local trailer="\"#;"
    # Prevent bash parsing of escape chars
    local body="$(wget -qO- https://raw.githubusercontent.com/edamametechnologies/threatmodels/$branch/threatmodel-$os.json)"
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
else
    # If an argument is provided, just use that
    update_threat_metrics $1
fi