# Build the offline wheel-house (vendor/) from requirements.txt.
# Run on a connected machine with the same interpreter as the demo laptop
# (Python 3.12, win_amd64). See vendor/README.md.
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
python -m pip download -r (Join-Path $repo "requirements.txt") -d (Join-Path $repo "vendor")
