# UDS 0x27 -> 0x2E Mutation Campaign

The corpus is deterministic and mutates gateway policy, diagnostic session
ordering, seed/key validity, DID selection and 0x2E payload length around
the paper-grounded SecurityAccess-derived write attack.

| Profile | Cases | Valid attack-shaped cases | Attack successes | Success rate | Blocked/failed rate | Hotpatch-blocked valid cases |
|---|---:|---:|---:|---:|---:|---:|
| before_hotpatch | 1000 | 787 | 787 | 78.70% | 21.30% | 0 |
| after_hotpatch | 1000 | 787 | 0 | 0.00% | 100.00% | 787 |

Interpretation: the pre-hotpatch success rate is below 100% because the
denominator includes mutated but plausible diagnostic attempts, not only
the single hand-picked successful chain. The post-hotpatch result is an
observed block rate over this corpus; untested attack variants remain out
of scope and should be stated as residual risk.
