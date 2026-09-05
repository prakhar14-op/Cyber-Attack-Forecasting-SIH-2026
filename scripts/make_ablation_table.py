"""Render the ablation table to Markdown for the README (M4.5).

    python scripts/make_ablation_table.py              # print at 1% FPR
    python scripts/make_ablation_table.py --budget 0.001

Reads results/*.json via eval.ablation — never hand-typed numbers.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eval import ablation  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--budget", type=float, default=0.01)
    args = parser.parse_args(argv)

    table = ablation.build_table(budget=args.budget)
    print(ablation.to_markdown(table, args.budget))
    return 0


if __name__ == "__main__":
    sys.exit(main())
