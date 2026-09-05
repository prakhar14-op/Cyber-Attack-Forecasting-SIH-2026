#!/usr/bin/env bash
# Download the configured CSE-CIC-IDS2018 days from the public bucket (M1.1).
#
#   data/download_cic.sh --dry-run     print the size plan, download nothing
#   data/download_cic.sh               print the size plan, then sync the files
#   data/download_cic.sh --ls          list every file under the processed prefix
#                                      (used by decision 001 to compare options)
#
# The day list lives in configs/data.yaml (dataset.days: [{date, csv}, ...]) —
# empty until docs/decisions/001-feature-source.md is signed off. Nothing is
# hardcoded here.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PY="$REPO_ROOT/.venv/Scripts/python.exe"
[ -x "$PY" ] || PY="python"

# The pip-installed aws launchers are broken on paths with spaces (this machine),
# so prefer driving awscli through whichever python can import it.
if python -c "import awscli" >/dev/null 2>&1; then
    aws_cli() { python -c "import sys, awscli.clidriver; sys.exit(awscli.clidriver.main())" "$@"; }
elif "$PY" -c "import awscli" >/dev/null 2>&1; then
    aws_cli() { "$PY" -c "import sys, awscli.clidriver; sys.exit(awscli.clidriver.main())" "$@"; }
else
    aws_cli() { aws "$@"; }
fi

BUCKET="$("$PY" -c "from configs import load_config; print(load_config('data')['dataset']['s3_bucket'])")"
PREFIX="$("$PY" -c "from configs import load_config; print(load_config('data')['dataset']['s3_prefix'])")"
RAW_DIR="$("$PY" -c "from configs import load_config, resolve_path; print(resolve_path(load_config('data')['paths']['raw_dir']))")"

if [ "${1:-}" = "--ls" ]; then
    aws_cli s3 ls --no-sign-request "$BUCKET/$PREFIX/" --human-readable
    exit 0
fi

mapfile -t CSVS < <("$PY" -c "
from configs import load_config
for day in load_config('data')['dataset']['days']:
    print(day['csv'])
")

if [ "${#CSVS[@]}" -eq 0 ]; then
    echo "No days configured in configs/data.yaml (dataset.days)."
    echo "That list is filled by docs/decisions/001-feature-source.md — run --ls to size the options."
    exit 1
fi

echo "Plan ($BUCKET/$PREFIX -> $RAW_DIR):"
TOTAL_BYTES=0
for csv in "${CSVS[@]}"; do
    LINE="$(aws_cli s3 ls --no-sign-request "$BUCKET/$PREFIX/$csv" | tail -1)"
    if [ -z "$LINE" ]; then
        echo "  MISSING IN BUCKET: $csv" >&2
        exit 1
    fi
    BYTES="$(echo "$LINE" | awk '{print $3}')"
    TOTAL_BYTES=$((TOTAL_BYTES + BYTES))
    printf "  %12s bytes  %s\n" "$BYTES" "$csv"
done
printf "  %12s bytes  TOTAL (~%s GB)\n" "$TOTAL_BYTES" "$(awk "BEGIN{printf \"%.1f\", $TOTAL_BYTES/1073741824}")"

if [ "${1:-}" = "--dry-run" ]; then
    echo "Dry run: nothing downloaded."
    exit 0
fi

mkdir -p "$RAW_DIR"
INCLUDES=()
for csv in "${CSVS[@]}"; do
    INCLUDES+=(--include "$csv")
done
aws_cli s3 sync --no-sign-request --exclude "*" "${INCLUDES[@]}" "$BUCKET/$PREFIX" "$RAW_DIR"
echo "Done. Files in $RAW_DIR:"
ls -la "$RAW_DIR"
