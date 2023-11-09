#!/bin/bash

if [ $# -eq 0 ]; then
    echo "Usage: $0 <macOS/Linux/Windows/iOS>"
    exit 1
fi

os=$1
os_lower=$(echo $os | tr '[:upper:]' '[:lower:]')
os_upper=$(echo $os | tr '[:lower:]' '[:upper:]')

echo "Updating threat metrics for $os / $os_lower / $os_upper"

branch=$(git rev-parse --abbrev-ref HEAD)
# Only deal with main and dev branches, default to dev
if [ $branch != "dev" ] && [ $branch != "main" ]; then
  branch=dev
fi
target=./src/threat_metrics_$os_lower.rs
header="// Built in default threat model\npub static THREAT_METRICS_$os_upper: &str = r#\""
trailer="\"#;"
# Prevent bash parsing of escape chars
body="$(wget -qO- https://raw.githubusercontent.com/edamametechnologies/threatmodels/$branch/threatmodel-$os.json)"
# Interpret escape chars
echo -n -e "$header" > "$target"
# Preserve escape chars 
echo -n "$body" >> "$target"
# Interpret escape chars
echo -e $trailer >> "$target"
