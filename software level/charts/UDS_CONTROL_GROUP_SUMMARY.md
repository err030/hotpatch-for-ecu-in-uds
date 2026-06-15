# UDS Benign-Control vs Attack-Mutation Summary

| Profile | Workload | Cases | Successes | Success rate | Blocked/failed rate |
|---|---|---:|---:|---:|---:|
| before_hotpatch | benign diagnostic | 1000 | 1000 | 100.00% | 0.00% |
| before_hotpatch | attack mutation | 1000 | 787 | 78.70% | 21.30% |
| after_hotpatch | benign diagnostic | 1000 | 1000 | 100.00% | 0.00% |
| after_hotpatch | attack mutation | 1000 | 0 | 0.00% | 100.00% |

Interpretation: benign diagnostic requests are expected to remain usable
before and after the hotpatch. The hotpatch should selectively reduce
attack mutation success, not break normal UDS diagnostic workflows.
