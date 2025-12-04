#!/bin/bash

# ==============================================================================
# Artifactory AQL Scanner (Shai-Hulud 2.0)
# ==============================================================================
# 1. Fetches Threat Intel from JFrog Research CSV.
# 2. Constructs filenames (name-version.tgz) for each entry.
# 3. Uses Artifactory Query Language (AQL) to find if these files exist.
# 4. Saves confirmed hits to a dedicated 'found_artifacts.csv' file.
# ==============================================================================

# ==============================================================================
# Help Information
# ==============================================================================
Help() {
   # Display Help
   echo "Add description of the script functions here."
   echo
   echo "Syntax: rt-aql-scanner.sh [-r|h|u]"
   echo "options:"
   echo "r     (Optional) Specify the repository you want to run the script against."
   echo "h     Print this Help."
   echo "u     Specify the Artifactory URL to run the script against."
   echo
}

# Parsing Command Line Arguments 
while getopts ":hru:" option; do
   case $option in
      h) # Show Help Information 
	 Help
	 exit;;
      r) # Specify Repo Name
         REPO=$OPTARG;;
      u) # Specify Artifactory URL
         ARTIFACTORY_URL=$OPTARG;;
     \?) # Invalid option
         echo "Error: Invalid option"
         exit;;
   esac
done

# --- Configuration ---
CSV_URL="https://research.jfrog.com/shai_hulud_2_packages.csv"
TEMP_DIR="aql_scan_tmp"
TARGET_LIST="$TEMP_DIR/targets.txt"

# Output Files
FULL_LOG="full_scan_log.csv"      # Contains every check (FOUND and NOT_FOUND)
FOUND_LOG="found_artifacts.csv"   # Contains ONLY items found in Artifactory

# --- Pre-flight Checks ---
# Check if ARTIFACTORY_URL is empty
if [ -z "$ARTIFACTORY_URL" ]; then
    echo "Error: ARTIFACTORY_URL argument (-u) is not set."
    echo "Usage: sh rt-aql-scanner.sh -u 'https://your-artifactory-url.com'"
    exit 1 # Exit with an error status
else
    echo "The ARTIFACTORY_URL (-u) is: $ARTIFACTORY_URL"
fi

if [ -z "$rt_token" ]; then
    echo "Error: Environment variable \$rt_token is not set."
    echo "Export it using: export rt_token='your_bearer_token'"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: 'jq' is required for this script."
    exit 1
fi

# Construct AQL Query
if [[ -n "$REPO" ]]; then
    AQL_QUERY="items.find({\"repo\":{\"\$eq\":\"$REPO\"},\"name\":{\"\$eq\":\"$FILE_NAME\"}})"
else
    AQL_QUERY="items.find({\"name\":{\"\$eq\":\"$FILE_NAME\"}})"
fi

mkdir -p "$TEMP_DIR"

# ==============================================================================
# Step 1: Fetch and Parse CSV
# ==============================================================================

echo "[1/3] Fetching Threat Intelligence feed..."
echo "      Source: $CSV_URL"

# Download CSV
if curl -sL "$CSV_URL" -o "$TEMP_DIR/feed.csv"; then
    echo "  -> Download successful."
else
    echo "Error: Failed to download CSV."
    exit 1
fi

# Parse CSV:
# Columns: package_name ($1), package_type ($2), versions ($3), xray_ids ($4)
# Logic:
# 1. Clean Package Name: Remove quotes and spaces.
# 2. Clean Versions: Remove quotes, spaces, and square brackets '[]'.
awk -F, 'NR>1 { 
    pkg=$1; 
    gsub(/["[:space:]]/, "", pkg);
    
    # Clean brackets and quotes from Column 3 ($3)
    raw_vers=$3;
    gsub(/[\[\]"[:space:]]/, "", raw_vers); # Remove [ and ] and quotes

    # Split versions by || using regex safe method
    n=split(raw_vers, vers, "[|][|]");
    for(i=1; i<=n; i++) {
        v=vers[i];
        if(pkg != "" && v != "") print pkg, v
    }
}' "$TEMP_DIR/feed.csv" | sort | uniq > "$TARGET_LIST"

TOTAL_TARGETS=$(wc -l < "$TARGET_LIST")
echo "  -> List Prepared. Found $TOTAL_TARGETS potential files to search."

# ==============================================================================
# Step 2: Query Artifactory using AQL
# ==============================================================================

echo "[2/3] Searching Artifactory via AQL..."

# Initialize Reports
echo "Package,Version,Filename,Status,Repo,Path" > "$FULL_LOG"
echo "Package,Version,Filename,Repo,Path" > "$FOUND_LOG"

COUNTER=0
FOUND_COUNT=0

while read -r pkg_name pkg_version; do
    COUNTER=$((COUNTER+1))
    
    # Construct Filename
    # Logic: 
    # 1. If scoped (@scope/pkg), remove everything up to the last slash to get 'pkg'.
    # 2. If normal (pkg), it stays 'pkg'.
    BASE_NAME="${pkg_name##*/}"
    FILE_NAME="${BASE_NAME}-${pkg_version}.tgz"

    # Progress bar effect
    printf "\rScanning [%s/%s]: %s                   " "$COUNTER" "$TOTAL_TARGETS" "$FILE_NAME"
    
    # Execute API Call
    RESPONSE=$(curl -s -X POST "$ARTIFACTORY_URL/artifactory/api/search/aql" \
      -H "Authorization: Bearer $rt_token" \
      -H "Content-Type: text/plain" \
      -d "$AQL_QUERY")

    # Parse Response using jq
    MATCH_COUNT=$(echo "$RESPONSE" | jq '.results | length')
    
    if [ "$MATCH_COUNT" -gt 0 ] 2>/dev/null; then
        FOUND_COUNT=$((FOUND_COUNT+1))
        echo ""
        echo "  [!] MATCH FOUND: $FILE_NAME"
        
        # 1. Write to FOUND_LOG (Cleaner, only confirmed hits)
        echo "$RESPONSE" | jq -r --arg pkg "$pkg_name" --arg ver "$pkg_version" --arg fn "$FILE_NAME" \
            '.results[] | "\($pkg),\($ver),\($fn),\(.repo),\(.path)"' >> "$FOUND_LOG"

        # 2. Write to FULL_LOG (For audit trail)
        echo "$RESPONSE" | jq -r --arg pkg "$pkg_name" --arg ver "$pkg_version" --arg fn "$FILE_NAME" \
            '.results[] | "\($pkg),\($ver),\($fn),FOUND,\(.repo),\(.path)"' >> "$FULL_LOG"
    else
        # Only write to FULL_LOG
        echo "$pkg_name,$pkg_version,$FILE_NAME,NOT_FOUND,," >> "$FULL_LOG"
    fi
    
done < "$TARGET_LIST"

echo "" 
echo "[3/3] Scan Complete."
echo "----------------------------------------------------"
echo "Total Scanned: $TOTAL_TARGETS"
echo "Matches Found: $FOUND_COUNT"
echo "----------------------------------------------------"
if [ "$FOUND_COUNT" -gt 0 ]; then
    echo "⚠️  CRITICAL: Malicious artifacts found! Review separate file:"
    echo "   -> $FOUND_LOG"
else
    echo "✅ No malicious artifacts found."
fi
echo "Full audit log saved to: $FULL_LOG"

# Cleanup
rm -rf "$TEMP_DIR"
