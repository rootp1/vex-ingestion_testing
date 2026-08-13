#!/usr/bin/env bash
# Empirically measures Red Hat CSAF/VEX feed volume and change rate.
set -euo pipefail
cd "$(dirname "$0")"

BASE="https://security.access.redhat.com/data/csaf/v2/vex"

echo "Fetching changes.csv (the feed's built-in incremental cursor)..."
curl -sL -o changes.csv "$BASE/changes.csv"
awk -F'"' '{print $2}' changes.csv > all_paths.txt

TOTAL_DOCS=$(wc -l < all_paths.txt)
echo "Total documents tracked in changes.csv: $TOTAL_DOCS"

echo "Sampling 30 random documents across all years for size distribution..."
sort -R all_paths.txt | head -30 > random_paths.txt
rm -f head_sizes.txt
while read -r p; do
  sz=$(curl -sL -o /dev/null -w "%{size_download}" "$BASE/$p")
  echo "$p $sz" >> head_sizes.txt
done < random_paths.txt

python3 - "$TOTAL_DOCS" <<'PYEOF'
import csv, datetime, sys
total_docs = int(sys.argv[1])

sizes = [int(l.split()[1]) for l in open("head_sizes.txt")]
avg = sum(sizes) / len(sizes)
print(f"Random-sample avg doc size: {avg/1024:.1f} KB (n={len(sizes)})")
print(f"Estimated full feed size: {total_docs*avg/1e9:.2f} GB")

rows = [r for r in csv.reader(open("changes.csv")) if len(r) >= 2]
latest = max(datetime.datetime.fromisoformat(r[1]) for r in rows)
print(f"Latest timestamp in feed: {latest}")
for hours, label in [(6,"6h"),(24,"24h"),(24*7,"7d"),(24*30,"30d")]:
    cutoff = latest - datetime.timedelta(hours=hours)
    n = sum(1 for r in rows if datetime.datetime.fromisoformat(r[1]) > cutoff)
    pct = 100*n/total_docs
    print(f"Changed in last {label}: {n} docs ({pct:.2f}% of feed)")
PYEOF
