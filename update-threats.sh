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
else
    # Loop through all targets
    for os in "${targets[@]}"; do
        update_threat_metrics $os $USE_LOCAL
    done
fi
