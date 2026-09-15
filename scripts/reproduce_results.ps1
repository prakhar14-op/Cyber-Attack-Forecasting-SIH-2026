<#
.SYNOPSIS
    Regenerate every results/*.json behind the published ablation table, in the
    order that actually produces it, then re-render the table.

.DESCRIPTION
    results/ is gitignored (it is derived, and CLAUDE.md forbids hand-entered
    numbers), so a fresh clone has no table inputs at all and
    scripts/make_ablation_table.py - which only READS results/ - prints
    "_No results yet_". This script is the missing producer.

    PREREQUISITES - all three, or this script refuses to start:

      1. THE DATASET, extracted. Every row trains on the window matrix built
         from the per-host pcap fetch, at paths.interim_dir in configs/data.yaml
         (default C:/sih26_data/interim), for all four days in
         configs/data.yaml -> dataset.days. Build it once with:
             bash data/download_cic.sh      # needs bash + AWS CLI; ~12.7 GiB
             python -m data.zip_fetch
             python -m data.extract
             python -m data.windows
         Re-run those three python steps here with -WithDataPipeline.

      2. THE ANONYMISATION KEY in $env:SIH26_HMAC_KEY (the variable name is read
         from configs/data.yaml -> anonymisation.key_env_var). data/anonymize.py
         refuses to run without it rather than fall back to a default, and every
         published row is measured under ONE standardised key - a different key
         produces different pseudonyms and a different (incomparable) table.

      3. THE VENV, with requirements.txt installed (docs/INSTALL.md).

    RUNTIME: TBD. Not measured - this machine has no dataset, so no full run has
    been timed here. Shape of the cost, from the code: the four torch rows (tgn,
    tgn_graft, tgn_graft_no_time2vec, tgn_graft_t2v_clamped) each retrain the
    TGN link-prediction encoder from scratch over the train-split events and
    dominate; lr and xgb are minutes; fused is seconds because it only reads its
    members' score dumps.

    ORDER MATTERS: eval/fused.py reads results/scores/{xgb,tgn}.npz - the score
    dumps the instrumented harness writes for its members - and raises
    FileNotFoundError if either is absent. The fused row therefore CANNOT be
    produced before xgb and tgn have run.

    STALE ROWS: eval/ablation.py globs results/*.json, so any leftover file from
    an unrelated run becomes a table row. Use -Clean to start from an empty
    results/ directory.

.PARAMETER Python
    Interpreter to run every step with. Relative paths resolve against the repo
    root. Default: the repo's .venv.

.PARAMETER Budget
    FPR budget the table is rendered at. The published table is 0.01.

.PARAMETER WithDataPipeline
    Also run zip_fetch -> extract -> windows before evaluating. The S3 download
    (data/download_cic.sh) is NOT run from here: it needs bash and the AWS CLI
    and moves ~12.7 GiB.

.PARAMETER Clean
    Delete results/*.json first so no stale row survives into the table.

.PARAMETER CheckOnly
    Run the prerequisite checks and stop. Nothing is trained, nothing is written.

.EXAMPLE
    scripts\reproduce_results.ps1 -CheckOnly
    scripts\reproduce_results.ps1 -Clean
#>

[CmdletBinding()]
param(
    [string]$Python = '.venv\Scripts\python.exe',
    [double]$Budget = 0.01,
    [switch]$WithDataPipeline,
    [switch]$Clean,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

if (-not [System.IO.Path]::IsPathRooted($Python)) { $Python = Join-Path $repo $Python }

function Write-Banner($text) {
    Write-Host ''
    Write-Host "=== $text" -ForegroundColor Cyan
}

function Fail($lines) {
    Write-Host ''
    Write-Host 'PREREQUISITES NOT MET - nothing was run.' -ForegroundColor Red
    foreach ($l in $lines) { Write-Host "  $l" -ForegroundColor Red }
    Write-Host ''
    Write-Host 'See the PREREQUISITES block at the top of this script, and docs/INSTALL.md.'
    exit 1
}

function Abort($lines) {
    Write-Host ''
    Write-Host 'STOPPED MID-RUN - the table was NOT rendered.' -ForegroundColor Red
    foreach ($l in $lines) { Write-Host "  $l" -ForegroundColor Red }
    exit 1
}

# ---- preflight -----------------------------------------------------------
# Interpreter first: every other check needs it (the dataset paths and the key
# variable name live in configs/data.yaml and are read through configs.loader,
# never duplicated here).

Write-Banner 'Preflight'

if (-not (Test-Path -LiteralPath $Python)) {
    Fail @(
        "interpreter not found: $Python",
        'Create the venv and install requirements.txt first (docs/INSTALL.md),',
        'or point at another interpreter with -Python <path>.'
    )
}

$preflight = @'
import os
import sys

sys.path.insert(0, os.getcwd())

problems = []
try:
    from configs import load_config, resolve_path
except Exception as exc:
    print(f'PROBLEM: cannot import configs ({exc!r}) - is requirements.txt installed?')
    raise SystemExit(1)

# Every lookup below is a contract with configs/data.yaml. A parse error or a
# renamed key must arrive as a PROBLEM line, not as a traceback the caller has
# to read: this block exists to diagnose, and a diagnosis that is a stack trace
# has failed at its one job.
try:
    cfg = load_config('data')
    key_var = cfg['anonymisation']['key_env_var']
    interim = resolve_path(cfg['paths']['interim_dir'])
    days = [day['date'] for day in cfg['dataset']['days']]
except Exception as exc:
    print(
        f'PROBLEM: configs/data.yaml did not yield the keys this script reads '
        f'({type(exc).__name__}: {exc}). Expected anonymisation.key_env_var, '
        f'paths.interim_dir, and dataset.days[].date.'
    )
    raise SystemExit(1)

if os.environ.get(key_var):
    print(f'  ok   {key_var} is set')
else:
    problems.append(
        f'{key_var} is unset. Every published row is measured under one '
        f'standardised key; data/anonymize.py refuses to run without it. '
        f'Set it from the team .env before re-running.'
    )

if not interim.exists():
    problems.append(
        f'extracted dataset missing: {interim} does not exist. Run the data '
        f'pipeline first (see PREREQUISITES), or pass -WithDataPipeline.'
    )
else:
    for date in days:
        for kind in ('flows', 'packets'):
            d = interim / date / kind
            try:
                n = len(list(d.glob('*.parquet'))) if d.exists() else 0
            except OSError as exc:
                problems.append(f'cannot list {d}: {exc}')
                continue
            if n == 0:
                problems.append(f'no {kind} parquet for {date} under {d}')
            else:
                print(f'  ok   {date}/{kind}: {n} parquet file(s)')

for problem in problems:
    print(f'PROBLEM: {problem}')
raise SystemExit(1 if problems else 0)
'@

# No `2>&1` and no capture. Under $ErrorActionPreference = 'Stop', Windows
# PowerShell 5.1 wraps every stderr line of a redirected native command in an
# ErrorRecord, which then terminates the script with a RemoteException instead
# of reaching Fail() below. Letting both streams go straight to the console
# keeps the child's own diagnosis intact and leaves $LASTEXITCODE meaningful.
try {
    & $Python -c $preflight
    $preflightOk = ($LASTEXITCODE -eq 0)
} catch {
    Fail @(
        "could not run the preflight with $Python : $($_.Exception.Message)",
        'Check that the interpreter is the venv python from docs/INSTALL.md.'
    )
}
if (-not $preflightOk) {
    Fail @('one or more prerequisites above are missing (lines marked PROBLEM).')
}

Write-Host '  ok   all prerequisites present' -ForegroundColor Green
if ($CheckOnly) { exit 0 }

# ---- run -----------------------------------------------------------------

function Invoke-Step($label, $arguments) {
    Write-Banner $label
    Write-Host "> $Python $($arguments -join ' ')"
    & $Python @arguments
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $label (exit $LASTEXITCODE)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

if ($Clean) {
    Write-Banner 'Clean'
    Get-ChildItem -Path (Join-Path $repo 'results') -Filter '*.json' -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host "  removing $($_.Name)"; Remove-Item -LiteralPath $_.FullName -Force }
}

if ($WithDataPipeline) {
    Invoke-Step 'Selective per-host pcap fetch' @('-m', 'data.zip_fetch')
    Invoke-Step 'Flow + packet feature extraction' @('-m', 'data.extract')
    Invoke-Step 'Window matrix + class-count report' @('-m', 'data.windows')
}

# Member rows. Each writes results/<name>.json AND results/scores/<name>.npz;
# the fusion below consumes the latter, so xgb and tgn are not optional.
$members = @(
    'lr',
    'xgb',
    'lstm',
    'tgn',
    'tgn_graft',
    'tgn_graft_no_time2vec',
    'tgn_graft_t2v_clamped'
)
foreach ($m in $members) {
    Invoke-Step "Row: $m" @('-m', 'eval.harness', '--model', $m)
}

# Fusion: rank-mean of the xgb and tgn score dumps (eval/fused.py MEMBERS).
foreach ($needed in @('xgb', 'tgn')) {
    $dump = Join-Path $repo "results\scores\$needed.npz"
    if (-not (Test-Path -LiteralPath $dump)) {
        Abort @("fused row needs $dump, which the '$needed' row should have written.",
                "Re-run: $Python -m eval.harness --model $needed")
    }
}
Invoke-Step 'Row: fused (rank-mean xgb + tgn)' @('-m', 'eval.harness', '--model', 'fused')

# Horizon rows. These use the per-horizon schema, carry no `test` block, and are
# deliberately dropped by eval/ablation.py - they back docs/limitations.md
# section 4, not the table.
Invoke-Step 'Per-horizon forecast head (docs/limitations.md)' @('-m', 'eval.harness', '--model', 'forecast')

# Invariant culture: a comma decimal separator would reach argparse as "0,01".
$budgetArg = $Budget.ToString([System.Globalization.CultureInfo]::InvariantCulture)
Invoke-Step "Render ablation table at budget $budgetArg" @('scripts/make_ablation_table.py', '--budget', $budgetArg)

Write-Banner 'Done'
Write-Host 'The table above is the one published in README.md and docs/architecture.md.'
Write-Host 'Paste it verbatim - CLAUDE.md forbids hand-editing any number in it.'
