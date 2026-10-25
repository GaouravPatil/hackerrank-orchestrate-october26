# Usage Report

## Final Full-Dataset Run

- Command: `python3 code/main.py`
- Requests processed: 518
- Output: root `output.csv`
- Full-run status distribution: 155 COMPLETE, 353 INCOMPLETE, 10 NOT_APPLICABLE
- Runtime: Python 3.14.8, standard library only
- Runtime model provider: none (deterministic parser and rule engine)
- Runtime model calls: 0
- Input tokens: 0
- Output tokens: 0
- Total tokens: 0
- Average tokens per request: 0
- Estimated runtime model cost: $0.00

## Development Assistant

- Harness: opencode
- Model: deepseek-v4.1-flash-free
- Development model calls are not part of the submitted runtime and are not counted in the per-request totals above.

## Notes

The solution does not call an external LLM at inference time. All identity resolution, evidence parsing, policy application, ordering, and serialization are deterministic and reproducible from `dataset/`.
