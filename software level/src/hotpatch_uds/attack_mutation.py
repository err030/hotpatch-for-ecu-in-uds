"""Deterministic mutation campaign for the UDS 0x27 -> 0x2E attack chain."""

from __future__ import annotations

import csv
import io
import random
from dataclasses import dataclass

from .client import UdsClient
from .ecu import HotpatchedECU, PatchedECU, VALID_WRITE_DID
from .gateway import (
    GATEWAY_MODE_MISCONFIGURED,
    GATEWAY_MODE_OPEN,
    GATEWAY_MODE_RESTRICTED,
)
from .protocol import UDSResponse
from .scenarios import build_gateway_routed_client_and_server, derive_key_from_seed
from .server import MockEcuServer


SESSION_EXTENDED = "extended"
SESSION_SKIP = "skip_session"
SESSION_RESET_AFTER_UNLOCK = "reset_after_unlock"

KEY_CORRECT = "correct_seed_key"
KEY_WRONG = "wrong_key"
KEY_SKIP = "skip_key"

PROFILE_BEFORE = "before_hotpatch"
PROFILE_AFTER = "after_hotpatch"

BENIGN_DEFAULT_SESSION = "default_session"
BENIGN_EXTENDED_SESSION = "extended_session"
BENIGN_READ_STATUS_DID = "read_status_did"
BENIGN_READ_CONFIG_DID = "read_config_did"
BENIGN_SECURITY_UNLOCK = "security_unlock"
BENIGN_EXTENDED_READ_SEQUENCE = "extended_read_sequence"


@dataclass(frozen=True)
class Uds2eMutationCase:
    case_id: int
    gateway_mode: str
    session_strategy: str
    key_strategy: str
    did: int
    data: bytes

    @property
    def name(self) -> str:
        return f"mut_{self.case_id:04d}"

    def valid_attack_shape(self) -> bool:
        return (
            self.gateway_mode in {GATEWAY_MODE_OPEN, GATEWAY_MODE_MISCONFIGURED}
            and self.session_strategy == SESSION_EXTENDED
            and self.key_strategy == KEY_CORRECT
            and self.did == VALID_WRITE_DID
            and 1 <= len(self.data) <= 4
        )


@dataclass(frozen=True)
class Uds2eMutationOutcome:
    profile: str
    case: Uds2eMutationCase
    attack_success: bool
    valid_attack_shape: bool
    session_response: str
    seed_response: str
    key_response: str
    write_response: str
    read_response: str
    failure_reason: str


@dataclass(frozen=True)
class Uds2eMutationSummary:
    profile: str
    total_cases: int
    valid_attack_shapes: int
    attack_successes: int
    hotpatch_blocked_valid_shapes: int

    @property
    def attack_success_rate(self) -> float:
        return self.attack_successes / self.total_cases if self.total_cases else 0.0

    @property
    def blocked_or_failed_rate(self) -> float:
        return 1.0 - self.attack_success_rate


@dataclass(frozen=True)
class UdsBenignDiagnosticCase:
    case_id: int
    gateway_mode: str
    operation: str


@dataclass(frozen=True)
class UdsBenignDiagnosticOutcome:
    profile: str
    case: UdsBenignDiagnosticCase
    passed: bool
    responses: tuple[str, ...]
    failure_reason: str


@dataclass(frozen=True)
class UdsBenignDiagnosticSummary:
    profile: str
    total_cases: int
    passed_cases: int

    @property
    def pass_rate(self) -> float:
        return self.passed_cases / self.total_cases if self.total_cases else 0.0


def build_uds_2e_mutation_corpus(
    count: int = 1000,
    seed: int = 20260615,
) -> tuple[Uds2eMutationCase, ...]:
    """Build a reproducible mutation corpus around the SecurityAccess write chain.

    The distribution intentionally keeps most cases close to the working attack
    chain, while mutating gateway policy, session ordering, key validity, DID and
    write length. This gives a high pre-hotpatch success rate without making the
    result a hand-picked single path.
    """
    rng = random.Random(seed)
    cases: list[Uds2eMutationCase] = []

    for case_id in range(count):
        gateway_mode = _weighted_choice(
            rng,
            (
                (GATEWAY_MODE_MISCONFIGURED, 0.94),
                (GATEWAY_MODE_OPEN, 0.04),
                (GATEWAY_MODE_RESTRICTED, 0.02),
            ),
        )
        session_strategy = _weighted_choice(
            rng,
            (
                (SESSION_EXTENDED, 0.95),
                (SESSION_SKIP, 0.03),
                (SESSION_RESET_AFTER_UNLOCK, 0.02),
            ),
        )
        key_strategy = _weighted_choice(
            rng,
            (
                (KEY_CORRECT, 0.95),
                (KEY_WRONG, 0.03),
                (KEY_SKIP, 0.02),
            ),
        )
        did = _weighted_choice(
            rng,
            (
                (VALID_WRITE_DID, 0.95),
                (0x1001, 0.02),
                (0x2222, 0.03),
            ),
        )
        data_length = _weighted_choice(
            rng,
            (
                (1, 0.22),
                (2, 0.28),
                (3, 0.22),
                (4, 0.20),
                (0, 0.04),
                (5, 0.04),
            ),
        )
        data = bytes(rng.randrange(0, 256) for _ in range(data_length))
        cases.append(
            Uds2eMutationCase(
                case_id=case_id,
                gateway_mode=gateway_mode,
                session_strategy=session_strategy,
                key_strategy=key_strategy,
                did=did,
                data=data,
            )
        )

    return tuple(cases)


def build_benign_diagnostic_corpus(
    count: int = 1000,
    seed: int = 20260616,
) -> tuple[UdsBenignDiagnosticCase, ...]:
    """Build benign UDS requests that should continue to work after hotpatching."""
    rng = random.Random(seed)
    cases: list[UdsBenignDiagnosticCase] = []
    for case_id in range(count):
        gateway_mode = _weighted_choice(
            rng,
            (
                (GATEWAY_MODE_MISCONFIGURED, 0.90),
                (GATEWAY_MODE_OPEN, 0.05),
                (GATEWAY_MODE_RESTRICTED, 0.05),
            ),
        )
        operation = _weighted_choice(
            rng,
            (
                (BENIGN_DEFAULT_SESSION, 0.15),
                (BENIGN_EXTENDED_SESSION, 0.20),
                (BENIGN_READ_STATUS_DID, 0.20),
                (BENIGN_READ_CONFIG_DID, 0.15),
                (BENIGN_SECURITY_UNLOCK, 0.20),
                (BENIGN_EXTENDED_READ_SEQUENCE, 0.10),
            ),
        )
        cases.append(
            UdsBenignDiagnosticCase(
                case_id=case_id,
                gateway_mode=gateway_mode,
                operation=operation,
            )
        )
    return tuple(cases)


def run_uds_2e_mutation_campaign(
    cases: tuple[Uds2eMutationCase, ...] | None = None,
    *,
    profile: str,
) -> tuple[Uds2eMutationOutcome, ...]:
    if profile not in {PROFILE_BEFORE, PROFILE_AFTER}:
        raise ValueError(f"Unsupported mutation profile: {profile}")

    selected_cases = cases if cases is not None else build_uds_2e_mutation_corpus()
    outcomes: list[Uds2eMutationOutcome] = []
    for case in selected_cases:
        server = MockEcuServer(HotpatchedECU() if profile == PROFILE_AFTER else PatchedECU())
        client = build_gateway_routed_client_and_server(server, gateway_mode=case.gateway_mode)
        outcomes.append(_run_single_case(profile, client, case))
    return tuple(outcomes)


def run_benign_diagnostic_campaign(
    cases: tuple[UdsBenignDiagnosticCase, ...] | None = None,
    *,
    profile: str,
) -> tuple[UdsBenignDiagnosticOutcome, ...]:
    if profile not in {PROFILE_BEFORE, PROFILE_AFTER}:
        raise ValueError(f"Unsupported benign diagnostic profile: {profile}")

    selected_cases = cases if cases is not None else build_benign_diagnostic_corpus()
    outcomes: list[UdsBenignDiagnosticOutcome] = []
    for case in selected_cases:
        server = MockEcuServer(HotpatchedECU() if profile == PROFILE_AFTER else PatchedECU())
        client = build_gateway_routed_client_and_server(server, gateway_mode=case.gateway_mode)
        outcomes.append(_run_single_benign_case(profile, client, case))
    return tuple(outcomes)


def summarize_uds_2e_mutation_outcomes(
    outcomes: tuple[Uds2eMutationOutcome, ...],
) -> Uds2eMutationSummary:
    if not outcomes:
        return Uds2eMutationSummary(
            profile="empty",
            total_cases=0,
            valid_attack_shapes=0,
            attack_successes=0,
            hotpatch_blocked_valid_shapes=0,
        )

    return Uds2eMutationSummary(
        profile=outcomes[0].profile,
        total_cases=len(outcomes),
        valid_attack_shapes=sum(1 for outcome in outcomes if outcome.valid_attack_shape),
        attack_successes=sum(1 for outcome in outcomes if outcome.attack_success),
        hotpatch_blocked_valid_shapes=sum(
            1
            for outcome in outcomes
            if outcome.valid_attack_shape and outcome.write_response == "7F2E31"
        ),
    )


def summarize_benign_diagnostic_outcomes(
    outcomes: tuple[UdsBenignDiagnosticOutcome, ...],
) -> UdsBenignDiagnosticSummary:
    if not outcomes:
        return UdsBenignDiagnosticSummary(profile="empty", total_cases=0, passed_cases=0)
    return UdsBenignDiagnosticSummary(
        profile=outcomes[0].profile,
        total_cases=len(outcomes),
        passed_cases=sum(1 for outcome in outcomes if outcome.passed),
    )


def mutation_detail_csv(outcomes: tuple[Uds2eMutationOutcome, ...]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        (
            "profile",
            "case_id",
            "gateway_mode",
            "session_strategy",
            "key_strategy",
            "did",
            "data_hex",
            "data_length",
            "valid_attack_shape",
            "attack_success",
            "session_response",
            "seed_response",
            "key_response",
            "write_response",
            "read_response",
            "failure_reason",
        )
    )
    for outcome in outcomes:
        case = outcome.case
        writer.writerow(
            (
                outcome.profile,
                case.case_id,
                case.gateway_mode,
                case.session_strategy,
                case.key_strategy,
                f"0x{case.did:04X}",
                case.data.hex().upper(),
                len(case.data),
                str(outcome.valid_attack_shape).lower(),
                str(outcome.attack_success).lower(),
                outcome.session_response,
                outcome.seed_response,
                outcome.key_response,
                outcome.write_response,
                outcome.read_response,
                outcome.failure_reason,
            )
        )
    return buffer.getvalue()


def mutation_summary_csv(summaries: tuple[Uds2eMutationSummary, ...]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        (
            "profile",
            "total_cases",
            "valid_attack_shapes",
            "attack_successes",
            "attack_success_rate",
            "blocked_or_failed_rate",
            "hotpatch_blocked_valid_shapes",
        )
    )
    for summary in summaries:
        writer.writerow(
            (
                summary.profile,
                summary.total_cases,
                summary.valid_attack_shapes,
                summary.attack_successes,
                f"{summary.attack_success_rate:.4f}",
                f"{summary.blocked_or_failed_rate:.4f}",
                summary.hotpatch_blocked_valid_shapes,
            )
        )
    return buffer.getvalue()


def mutation_summary_markdown(summaries: tuple[Uds2eMutationSummary, ...]) -> str:
    lines = [
        "# UDS 0x27 -> 0x2E Mutation Campaign",
        "",
        "The corpus is deterministic and mutates gateway policy, diagnostic session",
        "ordering, seed/key validity, DID selection and 0x2E payload length around",
        "the paper-grounded SecurityAccess-derived write attack.",
        "",
        "| Profile | Cases | Valid attack-shaped cases | Attack successes | Success rate | Blocked/failed rate | Hotpatch-blocked valid cases |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for summary in summaries:
        lines.append(
            "| "
            f"{summary.profile} | "
            f"{summary.total_cases} | "
            f"{summary.valid_attack_shapes} | "
            f"{summary.attack_successes} | "
            f"{summary.attack_success_rate:.2%} | "
            f"{summary.blocked_or_failed_rate:.2%} | "
            f"{summary.hotpatch_blocked_valid_shapes} |"
        )

    lines.extend(
        (
            "",
            "Interpretation: the pre-hotpatch success rate is below 100% because the",
            "denominator includes mutated but plausible diagnostic attempts, not only",
            "the single hand-picked successful chain. The post-hotpatch result is an",
            "observed block rate over this corpus; untested attack variants remain out",
            "of scope and should be stated as residual risk.",
            "",
        )
    )
    return "\n".join(lines)


def benign_detail_csv(outcomes: tuple[UdsBenignDiagnosticOutcome, ...]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        (
            "profile",
            "case_id",
            "gateway_mode",
            "operation",
            "passed",
            "responses",
            "failure_reason",
        )
    )
    for outcome in outcomes:
        writer.writerow(
            (
                outcome.profile,
                outcome.case.case_id,
                outcome.case.gateway_mode,
                outcome.case.operation,
                str(outcome.passed).lower(),
                " ".join(outcome.responses),
                outcome.failure_reason,
            )
        )
    return buffer.getvalue()


def control_group_summary_csv(
    benign_summaries: tuple[UdsBenignDiagnosticSummary, ...],
    attack_summaries: tuple[Uds2eMutationSummary, ...],
) -> str:
    attack_by_profile = {summary.profile: summary for summary in attack_summaries}
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        (
            "profile",
            "workload",
            "total_cases",
            "successful_cases",
            "success_rate",
            "blocked_or_failed_rate",
        )
    )
    for benign in benign_summaries:
        writer.writerow(
            (
                benign.profile,
                "benign_diagnostic",
                benign.total_cases,
                benign.passed_cases,
                f"{benign.pass_rate:.4f}",
                f"{1.0 - benign.pass_rate:.4f}",
            )
        )
        attack = attack_by_profile[benign.profile]
        writer.writerow(
            (
                attack.profile,
                "attack_mutation",
                attack.total_cases,
                attack.attack_successes,
                f"{attack.attack_success_rate:.4f}",
                f"{attack.blocked_or_failed_rate:.4f}",
            )
        )
    return buffer.getvalue()


def control_group_summary_markdown(
    benign_summaries: tuple[UdsBenignDiagnosticSummary, ...],
    attack_summaries: tuple[Uds2eMutationSummary, ...],
) -> str:
    attack_by_profile = {summary.profile: summary for summary in attack_summaries}
    lines = [
        "# UDS Benign-Control vs Attack-Mutation Summary",
        "",
        "| Profile | Workload | Cases | Successes | Success rate | Blocked/failed rate |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for benign in benign_summaries:
        rows = (
            (
                benign.profile,
                "benign diagnostic",
                benign.total_cases,
                benign.passed_cases,
                benign.pass_rate,
                1.0 - benign.pass_rate,
            ),
            (
                benign.profile,
                "attack mutation",
                attack_by_profile[benign.profile].total_cases,
                attack_by_profile[benign.profile].attack_successes,
                attack_by_profile[benign.profile].attack_success_rate,
                attack_by_profile[benign.profile].blocked_or_failed_rate,
            ),
        )
        for profile, workload, total, successes, success_rate, blocked_rate in rows:
            lines.append(
                f"| {profile} | {workload} | {total} | {successes} | "
                f"{success_rate:.2%} | {blocked_rate:.2%} |"
            )
    lines.extend(
        (
            "",
            "Interpretation: benign diagnostic requests are expected to remain usable",
            "before and after the hotpatch. The hotpatch should selectively reduce",
            "attack mutation success, not break normal UDS diagnostic workflows.",
            "",
        )
    )
    return "\n".join(lines)


def mutation_rates_svg(summaries: tuple[Uds2eMutationSummary, ...]) -> str:
    bar_max_width = 520
    rows = []
    palette = {
        PROFILE_BEFORE: "#d95f02",
        PROFILE_AFTER: "#1b9e77",
    }
    labels = {
        PROFILE_BEFORE: "Before hotpatch",
        PROFILE_AFTER: "After hotpatch",
    }
    for index, summary in enumerate(summaries):
        y = 145 + index * 120
        width = max(1, int(summary.attack_success_rate * bar_max_width))
        color = palette.get(summary.profile, "#7570b3")
        rows.append(
            f'<text x="70" y="{y + 24}" font-size="24" font-family="Arial" fill="#202020">'
            f'{labels.get(summary.profile, summary.profile)}</text>'
        )
        rows.append(
            f'<rect x="310" y="{y}" width="{bar_max_width}" height="44" fill="#efefef" />'
        )
        rows.append(
            f'<rect x="310" y="{y}" width="{width}" height="44" fill="{color}" />'
        )
        rows.append(
            f'<text x="850" y="{y + 30}" font-size="24" font-family="Arial" fill="#202020">'
            f'{summary.attack_success_rate:.1%} attack success '
            f'({summary.attack_successes}/{summary.total_cases})</text>'
        )

    return """<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="430" viewBox="0 0 1280 430">
  <rect width="1280" height="430" fill="white"/>
  <text x="70" y="62" font-size="34" font-family="Arial" font-weight="700" fill="#202020">UDS 0x27 to 0x2E Mutation Campaign</text>
  <text x="70" y="101" font-size="21" font-family="Arial" fill="#444444">Attack success rate over a deterministic 1000-case mutated corpus</text>
  %s
  <text x="70" y="390" font-size="18" font-family="Arial" fill="#555555">Post-hotpatch block rate is observed for this corpus, not a proof over all possible inputs.</text>
</svg>
""" % "\n  ".join(rows)


def _run_single_case(
    profile: str,
    client: UdsClient,
    case: Uds2eMutationCase,
) -> Uds2eMutationOutcome:
    session_response = "-"
    seed_response = "-"
    key_response = "-"
    write_response = "-"
    read_response = "-"
    failure_reason = "not_evaluated"

    try:
        if case.session_strategy != SESSION_SKIP:
            session_response = _payload_hex(client.change_to_extended_session().response)

        seed_result = None
        if case.key_strategy != KEY_SKIP:
            seed_result = client.request_seed()
            seed_response = _payload_hex(seed_result.response)
            key = derive_key_from_seed(seed_result.response)
            if case.key_strategy == KEY_WRONG:
                key = bytes(byte ^ 0xFF for byte in key)
            key_response = _payload_hex(client.send_key(key).response)

        if case.session_strategy == SESSION_RESET_AFTER_UNLOCK:
            session_response = _payload_hex(client.change_to_default_session().response)

        write_result = client.write_data_by_identifier(case.did, case.data)
        write_response = _payload_hex(write_result.response)

        read_result = client.read_data_by_identifier(case.did)
        read_response = _payload_hex(read_result.response)
    except Exception as exc:  # noqa: BLE001 - this harness records transport drops too.
        failure_reason = exc.__class__.__name__
        return Uds2eMutationOutcome(
            profile=profile,
            case=case,
            attack_success=False,
            valid_attack_shape=case.valid_attack_shape(),
            session_response=session_response,
            seed_response=seed_response,
            key_response=key_response,
            write_response=write_response,
            read_response=read_response,
            failure_reason=failure_reason,
        )

    expected_readback = "62" + f"{case.did:04X}" + case.data.hex().upper()
    attack_success = write_response == "6E" + f"{case.did:04X}" and read_response == expected_readback
    if attack_success:
        failure_reason = "-"
    elif write_response == "7F2E31":
        failure_reason = "write_rejected_request_out_of_range"
    elif write_response == "7F2E33":
        failure_reason = "write_rejected_security_access_denied"
    elif write_response == "7F2E13":
        failure_reason = "write_rejected_length"
    else:
        failure_reason = "mutation_not_successful"

    return Uds2eMutationOutcome(
        profile=profile,
        case=case,
        attack_success=attack_success,
        valid_attack_shape=case.valid_attack_shape(),
        session_response=session_response,
        seed_response=seed_response,
        key_response=key_response,
        write_response=write_response,
        read_response=read_response,
        failure_reason=failure_reason,
    )


def _run_single_benign_case(
    profile: str,
    client: UdsClient,
    case: UdsBenignDiagnosticCase,
) -> UdsBenignDiagnosticOutcome:
    responses: list[str] = []
    try:
        if case.operation == BENIGN_DEFAULT_SESSION:
            responses.append(_payload_hex(client.change_to_default_session().response))
        elif case.operation == BENIGN_EXTENDED_SESSION:
            responses.append(_payload_hex(client.change_to_extended_session().response))
        elif case.operation == BENIGN_READ_STATUS_DID:
            responses.append(_payload_hex(client.read_data_by_identifier(0x1001).response))
        elif case.operation == BENIGN_READ_CONFIG_DID:
            responses.append(_payload_hex(client.read_data_by_identifier(VALID_WRITE_DID).response))
        elif case.operation == BENIGN_SECURITY_UNLOCK:
            responses.extend(_run_security_unlock(client))
        elif case.operation == BENIGN_EXTENDED_READ_SEQUENCE:
            responses.append(_payload_hex(client.change_to_extended_session().response))
            responses.append(_payload_hex(client.read_data_by_identifier(0x1001).response))
            responses.append(_payload_hex(client.read_data_by_identifier(VALID_WRITE_DID).response))
        else:
            raise ValueError(f"Unsupported benign diagnostic operation: {case.operation}")
    except Exception as exc:  # noqa: BLE001 - records transport and parser failures.
        return UdsBenignDiagnosticOutcome(
            profile=profile,
            case=case,
            passed=False,
            responses=tuple(responses),
            failure_reason=exc.__class__.__name__,
        )

    passed = all(not response.startswith("7F") for response in responses)
    return UdsBenignDiagnosticOutcome(
        profile=profile,
        case=case,
        passed=passed,
        responses=tuple(responses),
        failure_reason="-" if passed else "negative_response",
    )


def _run_security_unlock(client: UdsClient) -> list[str]:
    responses: list[str] = []
    responses.append(_payload_hex(client.change_to_extended_session().response))
    seed_result = client.request_seed()
    responses.append(_payload_hex(seed_result.response))
    responses.append(_payload_hex(client.send_key(derive_key_from_seed(seed_result.response)).response))
    return responses


def _payload_hex(response: UDSResponse) -> str:
    return response.to_payload().hex().upper()


def _weighted_choice(rng: random.Random, weighted_values: tuple[tuple[object, float], ...]):
    draw = rng.random()
    cursor = 0.0
    for value, weight in weighted_values:
        cursor += weight
        if draw <= cursor:
            return value
    return weighted_values[-1][0]
