"""Export thesis-ready charts for the UDS SecurityAccess mutation campaign."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.hotpatch_uds.attack_mutation import (  # noqa: E402
    PROFILE_AFTER,
    PROFILE_BEFORE,
    build_uds_2e_mutation_corpus,
    mutation_detail_csv,
    mutation_rates_svg,
    mutation_summary_csv,
    mutation_summary_markdown,
    run_uds_2e_mutation_campaign,
    summarize_uds_2e_mutation_outcomes,
)


CHARTS_DIR = ROOT / "charts"


def main() -> None:
    corpus = build_uds_2e_mutation_corpus(count=1000)
    before = run_uds_2e_mutation_campaign(corpus, profile=PROFILE_BEFORE)
    after = run_uds_2e_mutation_campaign(corpus, profile=PROFILE_AFTER)
    summaries = (
        summarize_uds_2e_mutation_outcomes(before),
        summarize_uds_2e_mutation_outcomes(after),
    )

    (CHARTS_DIR / "uds_2e_mutation_attack_detail.csv").write_text(
        mutation_detail_csv(before + after),
        encoding="utf-8",
    )
    (CHARTS_DIR / "uds_2e_mutation_attack_summary.csv").write_text(
        mutation_summary_csv(summaries),
        encoding="utf-8",
    )
    (CHARTS_DIR / "UDS_2E_MUTATION_ATTACK_SUMMARY.md").write_text(
        mutation_summary_markdown(summaries),
        encoding="utf-8",
    )
    (CHARTS_DIR / "uds_2e_mutation_attack_rates.svg").write_text(
        mutation_rates_svg(summaries),
        encoding="utf-8",
    )

    for summary in summaries:
        print(
            f"{summary.profile}: {summary.attack_successes}/{summary.total_cases} "
            f"successes ({summary.attack_success_rate:.2%})"
        )


if __name__ == "__main__":
    main()
