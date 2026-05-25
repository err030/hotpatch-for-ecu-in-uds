from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.hotpatch_uds.evaluation import (
    evaluate_default_hotpatch_value,
    hotpatch_evaluation_csv,
    hotpatch_evaluation_markdown,
)


def svg_bar(x: int, y: int, width: int, height: int, fill: str, label: str, value: str) -> str:
    return (
        f'<rect x="{x}" y="{y}" width="{width}" height="{height}" rx="12" fill="{fill}" />'
        f'<text x="{x + 12}" y="{y - 10}" font-size="18" fill="#202020">{label}</text>'
        f'<text x="{x + width + 10}" y="{y + height - 8}" font-size="18" fill="#202020">{value}</text>'
    )


def build_svg() -> str:
    summary = evaluate_default_hotpatch_value()
    attack = summary.attack_resistance

    exposure_max = max(
        summary.ota_only_cumulative_exposure_window_min,
        summary.hotpatch_first_cumulative_exposure_window_min,
        1,
    )
    exposure_scale = 420 / exposure_max

    block_rate_max_width = 420
    hotpatch_block_width = max(int(attack.hotpatch_block_rate * block_rate_max_width), 1)
    ota_block_width = max(int(attack.ota_only_block_rate * block_rate_max_width), 1)

    ota_exposure_width = max(
        int(summary.ota_only_cumulative_exposure_window_min * exposure_scale),
        1,
    )
    hotpatch_exposure_width = max(
        int(summary.hotpatch_first_cumulative_exposure_window_min * exposure_scale),
        1,
    )

    stat_lines = [
        f"Reserved memory: {summary.reserved_memory_bytes} B",
        f"Peak quarantine: {summary.peak_quarantine_bytes} B",
        f"Peak active code: {summary.peak_active_code_bytes} B",
        f"Validation+scheduling+apply: "
        f"{summary.validation_total_ms + summary.scheduling_total_ms + summary.application_total_ms:.3f} ms",
        f"Guard overhead: {summary.guard_overhead_total_ms:.3f} ms",
        f"Attack chain latency vulnerable/patched: "
        f"{summary.vulnerable_attack_chain_latency_ms:.3f} / {summary.patched_attack_chain_latency_ms:.3f} ms",
        f"Exposure reduction ratio: {summary.exposure_window_reduction_ratio}",
    ]

    stat_svg = []
    for index, line in enumerate(stat_lines):
        stat_svg.append(
            f'<text x="640" y="{180 + index * 34}" font-size="20" fill="#202020">{line}</text>'
        )

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="760" viewBox="0 0 1200 760">
<rect width="1200" height="760" fill="#fffaf3" />
<text x="60" y="60" font-size="34" font-weight="700" fill="#202020">Hotpatch Evaluation For UDS-on-CAN</text>
<text x="60" y="96" font-size="20" fill="#454545">software-level assessment of exposure reduction, attack blocking, resource usage and timing overhead</text>

<text x="60" y="150" font-size="26" font-weight="700" fill="#202020">Cumulative Exposure Window</text>
{svg_bar(60, 180, ota_exposure_width, 38, "#f4a261", "OTA-only", f"{summary.ota_only_cumulative_exposure_window_min} min")}
{svg_bar(60, 250, hotpatch_exposure_width, 38, "#2a9d8f", "Hotpatch-first", f"{summary.hotpatch_first_cumulative_exposure_window_min} min")}

<text x="60" y="360" font-size="26" font-weight="700" fill="#202020">Attack Block Rate In OTA Window</text>
{svg_bar(60, 390, hotpatch_block_width, 38, "#2a9d8f", "Hotpatch block rate", f"{attack.hotpatch_block_rate:.2%}")}
{svg_bar(60, 460, ota_block_width, 38, "#e76f51", "OTA-only block rate", f"{attack.ota_only_block_rate:.2%}")}

<text x="640" y="150" font-size="26" font-weight="700" fill="#202020">Resource And Real-Time Notes</text>
{''.join(stat_svg)}

<rect x="640" y="470" width="470" height="180" rx="18" fill="#f1f5f9" stroke="#d6dce4" />
<text x="665" y="510" font-size="22" font-weight="700" fill="#202020">Interpretation</text>
<text x="665" y="548" font-size="19" fill="#202020">Hotpatch-first shrinks the exposure window before full OTA completion.</text>
<text x="665" y="580" font-size="19" fill="#202020">The software model shows a modest latency increase but earlier blocking.</text>
<text x="665" y="612" font-size="19" fill="#202020">This is evidence for thesis-level plausibility, not hardware proof.</text>
</svg>
"""
    return svg


def main() -> None:
    summary = evaluate_default_hotpatch_value()
    csv_path = ROOT / "hotpatch_evaluation_default.csv"
    md_path = ROOT / "HOTPATCH_EVALUATION_default.md"
    svg_path = ROOT / "hotpatch_evaluation_default.svg"

    csv_path.write_text(hotpatch_evaluation_csv(summary), encoding="utf-8")
    md_path.write_text(hotpatch_evaluation_markdown(summary), encoding="utf-8")
    svg_path.write_text(build_svg(), encoding="utf-8")

    print(csv_path)
    print(md_path)
    print(svg_path)


if __name__ == "__main__":
    main()
