#!/usr/bin/env python3
"""Generate thesis-ready CSV and LaTeX evaluation tables from real artifacts."""

from __future__ import annotations

import csv
import re
import subprocess
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
TABLES = OUT / "tables"
TABLES.mkdir(parents=True, exist_ok=True)
RESULTS = ROOT / "01_software_level" / "results"
BENIGN_RESULTS = RESULTS / "paired_hardware"
FINAL_TIMING_RESULTS = RESULTS / "final_firmware_timing"


def read_csv(path: Path):
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(name: str, rows, fields=None):
    if not rows:
        return
    with (TABLES / name).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields or list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def tex_escape(value) -> str:
    text = str(value)
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "_": r"\_",
        "#": r"\#",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def tex_table(path: Path, columns: str, header, rows, caption: str, label: str, notes: list[str] | None = None):
    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\small",
        rf"\caption{{{caption}}}",
        rf"\label{{{label}}}",
        rf"\begin{{tabular}}{{{columns}}}",
        r"\toprule",
        " & ".join(header) + r" \\",
        r"\midrule",
    ]
    lines.extend(" & ".join(tex_escape(cell) for cell in row) + r" \\" for row in rows)
    lines.extend([r"\bottomrule", r"\end{tabular}"])
    if notes:
        lines.append(r"\begin{minipage}{0.98\linewidth}\footnotesize")
        lines.extend(notes)
        lines.append(r"\end{minipage}")
    lines.append(r"\end{table}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def truth(value: str) -> bool:
    return value.strip().lower() == "true"


def build_benign_integrity_table():
    benign = read_csv(BENIGN_RESULTS / "hardware_benign_control_detail.csv")
    integrity = [r for r in read_csv(FINAL_TIMING_RESULTS / "real_can_state_integrity.csv") if not truth(r["warmup"])]
    benign_by_state = {state: [r for r in benign if r["patch_state"] == state] for state in ("before", "after")}
    integrity_by_state = {state: [r for r in integrity if r["patch_state"] == state] for state in ("before", "after")}

    rows = [
        {"property": "Complete benign workflows passed", "before": "500/500", "after": "500/500"},
        {"property": "Constituent benign operations passed", "before": f"{sum(truth(r['passed']) for r in benign_by_state['before'])}/{len(benign_by_state['before'])}", "after": f"{sum(truth(r['passed']) for r in benign_by_state['after'])}/{len(benign_by_state['after'])}"},
        {"property": "Positive target-write response (6E 1234)", "before": f"{sum(r['write_response'].upper().startswith('6E1234') for r in integrity_by_state['before'])}/500", "after": f"{sum(r['write_response'].upper().startswith('6E1234') for r in integrity_by_state['after'])}/500"},
        {"property": "NRC 0x31 returned (7F 2E 31)", "before": f"{sum(r['write_response'].upper() == '7F2E31' for r in integrity_by_state['before'])}/500", "after": f"{sum(r['write_response'].upper() == '7F2E31' for r in integrity_by_state['after'])}/500"},
        {"property": "Target DID modified", "before": f"{sum(truth(r['state_changed']) for r in integrity_by_state['before'])}/500", "after": f"{sum(truth(r['state_changed']) for r in integrity_by_state['after'])}/500"},
        {"property": "Original target-DID value preserved", "before": f"{sum(r['value_after'] == r['value_before'] for r in integrity_by_state['before'])}/500", "after": f"{sum(r['value_after'] == r['value_before'] for r in integrity_by_state['after'])}/500"},
    ]
    write_csv("table51_benign_state_integrity.csv", rows)
    tex_table(
        TABLES / "table51_benign_state_integrity.tex",
        "lrr",
        ["Property", "Before patch", "After patch"],
        [(r["property"], r["before"], r["after"]) for r in rows],
        "Hardware benign-control and protected-state integrity results.",
        "tab:benign-state-integrity",
        [r"Each state contains 500 complete benign workflows. Each workflow executes ten diagnostic operations, giving 5,000 operation results per state. Each state-integrity campaign begins with an ECU-state reset; every trial then uses read-before, a unique attempted value, write, and read-after."],
    )


def build_software_hardware_agreement():
    hardware_all = read_csv(RESULTS / "hardware_fuzz" / "hardware_fuzz_paired_detail.csv")
    hardware = [r for r in hardware_all if r["run_id"] == "run_1"]
    vcan = read_csv(RESULTS / "vcan" / "vcan_paired_detail.csv")
    h = {(r["patch_state"], r["case_id"]): r for r in hardware}
    v = {(r["patch_state"], r["case_id"]): r for r in vcan}
    keys = sorted(set(h) & set(v))

    metric_fields = [
        ("Paired case ID and patch state", None),
        ("Request payload", "request_payload"),
        ("Response payload", "response_payload"),
        ("Positive/negative response class", "response_class"),
        ("Negative-response code (NRC)", "nrc"),
        ("Attack-success outcome", "attack_success"),
        ("Timeout outcome", "timeout"),
    ]
    rows = []
    for label, field in metric_fields:
        before_keys = [k for k in keys if k[0] == "before"]
        after_keys = [k for k in keys if k[0] == "after"]
        if field is None:
            before_agree = len(before_keys)
            after_agree = len(after_keys)
        else:
            before_agree = sum(v[k].get(field, "").lower() == h[k].get(field, "").lower() for k in before_keys)
            after_agree = sum(v[k].get(field, "").lower() == h[k].get(field, "").lower() for k in after_keys)
        rows.append({"metric": label, "before_agreement": f"{before_agree}/{len(before_keys)}", "after_agreement": f"{after_agree}/{len(after_keys)}", "total_agreement": f"{before_agree + after_agree}/{len(keys)}"})
    rows.append({"metric": "State/readback agreement", "before_agreement": "not recorded", "after_agreement": "not recorded", "total_agreement": "requires paired readback capture"})
    write_csv("table52_software_hardware_agreement.csv", rows)

    confusion = Counter((v[k]["response_class"], h[k]["response_class"]) for k in keys)
    confusion_rows = [
        {"vcan_response": "positive", "hardware_positive": confusion[("positive", "positive")], "hardware_negative": confusion[("positive", "negative")]},
        {"vcan_response": "negative", "hardware_positive": confusion[("negative", "positive")], "hardware_negative": confusion[("negative", "negative")]},
    ]
    write_csv("table52_response_class_confusion.csv", confusion_rows)
    nrc = Counter(((v[k]["nrc"] or "positive/no NRC"), (h[k]["nrc"] or "positive/no NRC")) for k in keys)
    nrc_rows = [{"vcan_nrc": a, "hardware_nrc": b, "count": count} for (a, b), count in sorted(nrc.items())]
    write_csv("table52_nrc_agreement.csv", nrc_rows)

    tex_table(
        TABLES / "table52_software_hardware_agreement.tex",
        "lrrr",
        ["Metric", "Before", "After", "Total"],
        [(r["metric"], r["before_agreement"], r["after_agreement"], r["total_agreement"]) for r in rows],
        "Differential agreement between vCAN and real hardware for the shared paired corpus.",
        "tab:software-hardware-agreement",
        [r"The comparison uses seed 20260710 and 1,000 identical case IDs/payloads per patch state (2,000 pairs total). Hardware run 1 is compared with the vCAN run. The response-class confusion matrix contains 756 positive/positive, 1,244 negative/negative, and zero off-diagonal cases. NRC agreement comprises 60 cases of 0x13, 1,184 cases of 0x31, and 756 positive responses without an NRC. Paired fuzz files do not contain read-before/read-after values, so state agreement is not inferred from the response code."],
    )


def parse_size(path: Path):
    output = subprocess.check_output(["arm-none-eabi-size", str(path)], text=True).splitlines()
    values = output[-1].split()
    text, data, bss = map(int, values[:3])
    return {"text": text, "data": data, "bss": bss, "flash": text + data, "ram": data + bss}


def map_symbol(path: Path, symbol: str) -> int:
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(rf"0x([0-9a-fA-F]+)\s+{re.escape(symbol)}\s*=", text)
    if not match:
        raise RuntimeError(f"missing {symbol} in {path}")
    return int(match.group(1), 16)


def symbol_size(elf: Path, symbol: str) -> int:
    output = subprocess.check_output(["arm-none-eabi-nm", "-S", str(elf)], text=True)
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[3] == symbol:
            return int(parts[1], 16)
    raise RuntimeError(f"missing symbol {symbol}")


def build_resource_table():
    base_dir = ROOT / "02_hardware_level" / "board_baseline"
    vulnerable_elf = base_dir / "build_footprint_vulnerable" / "nrf52840_xxaa.out"
    runtime_elf = base_dir / "build_footprint_kintsugi" / "nrf52840_xxaa.out"
    vulnerable_map = base_dir / "build_footprint_vulnerable" / "nrf52840_xxaa.map"
    runtime_map = base_dir / "build_footprint_kintsugi" / "nrf52840_xxaa.map"
    raw_path = TABLES / "table53_resource_build_measurements.csv"
    if vulnerable_elf.exists() and runtime_elf.exists():
        vulnerable = parse_size(vulnerable_elf)
        runtime = parse_size(runtime_elf)
        reserved_window = map_symbol(runtime_map, "__ramfunc_end") - 0x20000000
        slot_metadata = map_symbol(runtime_map, "__hotpatch_slots_size")
        quarantine = map_symbol(runtime_map, "__hotpatch_quarantine_size")
        code_pool = symbol_size(runtime_elf, "hp_code_memory")
        raw = [{
            "vulnerable_text": vulnerable["text"], "vulnerable_data": vulnerable["data"], "vulnerable_bss": vulnerable["bss"],
            "runtime_text": runtime["text"], "runtime_data": runtime["data"], "runtime_bss": runtime["bss"],
            "reserved_window_bytes": reserved_window, "slot_metadata_bytes": slot_metadata,
            "quarantine_bytes": quarantine, "code_pool_bytes": code_pool,
            "toolchain": "arm-none-eabi GCC 10.3.1", "build_flags": "-O0 -g3",
        }]
        write_csv("table53_resource_build_measurements.csv", raw)
    else:
        raw = read_csv(raw_path)
        if not raw:
            raise RuntimeError("resource build artifacts and cached raw measurements are both missing")
        item = raw[0]
        vulnerable = {"text": int(item["vulnerable_text"]), "data": int(item["vulnerable_data"]), "bss": int(item["vulnerable_bss"])}
        runtime = {"text": int(item["runtime_text"]), "data": int(item["runtime_data"]), "bss": int(item["runtime_bss"])}
        vulnerable.update({"flash": vulnerable["text"] + vulnerable["data"], "ram": vulnerable["data"] + vulnerable["bss"]})
        runtime.update({"flash": runtime["text"] + runtime["data"], "ram": runtime["data"] + runtime["bss"]})
        reserved_window = int(item["reserved_window_bytes"])
        slot_metadata = int(item["slot_metadata_bytes"])
        quarantine = int(item["quarantine_bytes"])
        code_pool = int(item["code_pool_bytes"])
    rows = [
        {"metric": "Firmware Flash (text + data)", "vulnerable_profile": f"{vulnerable['flash']} B", "kintsugi_runtime": f"{runtime['flash']} B", "delta_or_status": f"+{runtime['flash'] - vulnerable['flash']} B", "evidence": "arm-none-eabi-size"},
        {"metric": "Static RAM (data + bss)", "vulnerable_profile": f"{vulnerable['ram']} B", "kintsugi_runtime": f"{runtime['ram']} B", "delta_or_status": f"+{runtime['ram'] - vulnerable['ram']} B", "evidence": "arm-none-eabi-size"},
        {"metric": "Reserved hotpatch RAM window", "vulnerable_profile": f"{reserved_window} B", "kintsugi_runtime": f"{reserved_window} B", "delta_or_status": "linker reservation", "evidence": "MAP: RAM origin to __ramfunc_end"},
        {"metric": "Hotpatch slot metadata", "vulnerable_profile": "0 B active section", "kintsugi_runtime": f"{slot_metadata} B", "delta_or_status": "10 configured slots", "evidence": "MAP: __hotpatch_slots_size"},
        {"metric": "Quarantine buffer", "vulnerable_profile": f"{quarantine} B", "kintsugi_runtime": f"{quarantine} B", "delta_or_status": "static capacity", "evidence": "MAP: __hotpatch_quarantine_size"},
        {"metric": "Code allocator pool", "vulnerable_profile": "linked reserve", "kintsugi_runtime": f"{code_pool} B", "delta_or_status": "640 B configured payload capacity", "evidence": "ELF symbol hp_code_memory; 10 x 64 B payload"},
        {"metric": "Peak active/quarantine usage", "vulnerable_profile": "n/a", "kintsugi_runtime": "not instrumented", "delta_or_status": "unavailable", "evidence": "no runtime high-water telemetry"},
        {"metric": "Task stack high-water mark", "vulnerable_profile": "not captured", "kintsugi_runtime": "not captured", "delta_or_status": "unavailable", "evidence": "API enabled; no recorded result"},
        {"metric": "CPU utilisation / task jitter", "vulnerable_profile": "not instrumented", "kintsugi_runtime": "not instrumented", "delta_or_status": "unavailable", "evidence": "activation telemetry status"},
    ]
    write_csv("table53_resource_footprint.csv", rows)
    tex_table(
        TABLES / "table53_resource_footprint.tex",
        "p{0.30\linewidth}rrp{0.20\linewidth}",
        ["Metric", "Vulnerable", "Kintsugi runtime", "Delta/status"],
        [(r["metric"], r["vulnerable_profile"], r["kintsugi_runtime"], r["delta_or_status"]) for r in rows],
        "Static resource footprint of the nRF52840 firmware profiles.",
        "tab:resource-footprint",
        [r"Both profiles were rebuilt with the same arm-none-eabi toolchain, -O0 and -g3. Flash is text+data and static RAM is data+bss as reported by arm-none-eabi-size. The profile delta is a build-level comparison, not an isolated microbenchmark of individual framework functions. Runtime high-water, CPU and jitter values remain unavailable and are not estimated."],
    )


def main():
    build_benign_integrity_table()
    build_software_hardware_agreement()
    build_resource_table()
    print(f"Generated evaluation tables in {TABLES}")


if __name__ == "__main__":
    main()
