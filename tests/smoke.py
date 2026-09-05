"""End-to-end smoke runner: `python -m tests.smoke`.

Runs the full pipeline (load -> features -> windows -> model -> forecasts ->
ledger -> verify) on the committed 1,000-flow fixture, with the network disabled,
and must finish in under 60 s (CLAUDE.md, definition of done).

Until M8 ships engine.predict this fails loudly — it never substitutes a stub
pipeline or synthetic output.
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.net_guard import network_disabled  # noqa: E402

TIME_BUDGET_SECONDS = 60


def run(csv_path: Path, out_dir: Path) -> dict:
    """Full pipeline over one CSV. Returns the summary dict the app also uses."""
    try:
        from engine import predict
    except ImportError as exc:
        raise RuntimeError(
            "smoke pipeline unavailable: engine.predict is not implemented yet (M8). "
            "The smoke runner does not substitute stubs for missing stages."
        ) from exc

    result = predict.predict_file(csv_path, out_dir=out_dir)

    from ledger import verify_cli

    ok, first_bad = verify_cli.verify(out_dir / "audit_chain.jsonl")
    result["ledger_verified"] = ok
    result["ledger_first_bad_index"] = first_bad
    return result


def main(argv: list[str] | None = None) -> int:
    from configs import load_config, resolve_path, set_seed

    cfg = load_config("data")
    set_seed(cfg["seed"])

    args = list(sys.argv[1:] if argv is None else argv)
    csv_path = Path(args[0]) if args else resolve_path(cfg["paths"]["fixture_csv"])
    if not csv_path.exists():
        print(f"smoke: input file not found: {csv_path}", file=sys.stderr)
        return 2

    started = time.perf_counter()
    with tempfile.TemporaryDirectory() as tmp, network_disabled():
        result = run(csv_path, out_dir=Path(tmp))
    elapsed = time.perf_counter() - started

    print(
        f"smoke: {result.get('n_flows', '?')} flows -> "
        f"{len(result.get('forecasts', []))} forecasts, "
        f"ledger_verified={result.get('ledger_verified')}, {elapsed:.1f}s"
    )
    if elapsed >= TIME_BUDGET_SECONDS:
        print(f"smoke: exceeded the {TIME_BUDGET_SECONDS}s budget", file=sys.stderr)
        return 1
    if not result.get("ledger_verified"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
