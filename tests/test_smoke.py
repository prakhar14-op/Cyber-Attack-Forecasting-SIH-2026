"""End-to-end smoke (CLAUDE.md definition of done, BUILD_PLAN M0/M12).

The full pipeline runs on the committed 1,000-flow fixture in under 60 s with
the network disabled, produces forecasts, and the written ledger verifies.
"""

from __future__ import annotations

import time

from tests import smoke


def test_full_pipeline_on_1000_flow_fixture_offline_under_60s(
    no_network, fixture_csv, tmp_path
):
    started = time.perf_counter()
    try:
        result = smoke.run(fixture_csv, out_dir=tmp_path)
    except RuntimeError as exc:
        import pytest

        pytest.fail(str(exc), pytrace=False)
    elapsed = time.perf_counter() - started

    assert elapsed < smoke.TIME_BUDGET_SECONDS, (
        f"smoke run took {elapsed:.1f}s, budget is {smoke.TIME_BUDGET_SECONDS}s"
    )
    assert result["n_flows"] == 1000, "fixture must flow through as exactly 1,000 rows"
    assert result["forecasts"], "pipeline produced no forecasts"
    assert result["ledger_verified"] is True, (
        f"ledger failed offline verification at record {result['ledger_first_bad_index']}"
    )
