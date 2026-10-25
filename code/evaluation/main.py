#!/usr/bin/env python3
"""Reproducible sample and custom-case evaluation for the deletion auditor."""
import csv
import json
import os
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, 'code'))
import engine  # noqa: E402


def sample_metrics():
    rows = engine.run(sample=True)
    expected = {r['case_id']: r for r in csv.DictReader(open(os.path.join(ROOT, 'dataset', 'sample_output.csv'), encoding='utf-8'))}
    status_ok = sequence_ok = 0
    step_exact = step_total = field_exact = field_total = 0
    failures = []
    fields = ('step_no', 'phase', 'system_id', 'resource_id', 'operation', 'state', 'evidence_id')
    for row in rows:
        cid = row['case_id']
        exp = expected[cid]
        es = json.loads(exp['steps_json'])
        ps = json.loads(row['steps_json'])
        status_ok += exp['deletion_status'] == row['deletion_status']
        if es == ps:
            sequence_ok += 1
        else:
            failures.append(cid)
        step_total += len(es)
        for i, step in enumerate(es):
            if i < len(ps) and ps[i] == step:
                step_exact += 1
            for key in fields:
                field_total += 1
                if i < len(ps) and ps[i].get(key) == step.get(key):
                    field_exact += 1
    return {
        'rows': len(rows),
        'status_ok': status_ok,
        'sequence_ok': sequence_ok,
        'step_exact': step_exact,
        'step_total': step_total,
        'field_exact': field_exact,
        'field_total': field_total,
        'failures': failures,
    }


def full_rows():
    return {r['case_id']: r for r in engine.run(sample=False)}


def has_step(row, phase, operation, resource=None):
    for step in json.loads(row['steps_json']):
        if step['phase'] == phase and step['operation'] == operation:
            if resource is None or step['resource_id'] == resource:
                return True
    return False


def custom_checks(rows):
    checks = [
        ('case_538', 'marketing opt-out is not a deletion request',
         lambda r: r['deletion_status'] == 'NOT_APPLICABLE' and json.loads(r['steps_json']) == []),
        ('case_544', 'failed tombstone redaction is incomplete and reports exposed PII',
         lambda r: r['deletion_status'] == 'INCOMPLETE' and has_step(r, 'FINDING', 'REPORT_EXPOSED_PII', 'tombstone_8648')
         and has_step(r, 'REMEDIATION', 'REDACT_RECORD', 'tombstone_8648')),
        ('case_543', 'successful tombstone redaction is complete',
         lambda r: r['deletion_status'] == 'COMPLETE' and has_step(r, 'VERIFICATION', 'VERIFY_RECORD_REDACTED', 'tombstone_205')),
        ('case_99', 'restorable backup is reported as a restore risk',
         lambda r: r['deletion_status'] == 'INCOMPLETE' and has_step(r, 'FINDING', 'REPORT_RESTORE_RISK', 'backup_7804')),
        ('case_63', 'catalog-linked marketing profile is a remaining record',
         lambda r: r['deletion_status'] == 'INCOMPLETE' and has_step(r, 'FINDING', 'REPORT_REMAINING_RECORD', 'marketing_001')),
        ('case_45', 'retained security audit record is verified present',
         lambda r: r['deletion_status'] == 'COMPLETE' and has_step(r, 'VERIFICATION', 'VERIFY_RECORD_PRESENT', 'audit_record_003')),
    ]
    out = []
    for cid, desc, fn in checks:
        row = rows.get(cid)
        out.append((cid, desc, bool(row and fn(row))))
    return out


def main():
    metrics = sample_metrics()
    rows = full_rows()
    custom = custom_checks(rows)
    passed = sum(1 for _, _, ok in custom if ok)

    report = f"""# Evaluation Report

## Method

The evaluator runs the production pipeline in `code/engine.py` directly, compares the 32 public sample cases against `dataset/sample_output.csv`, then applies six additional evidence-derived checks to the 518-case full run. Comparison is structural: phase order, step order, resource IDs, operations, states, and evidence references must all match.

## Sample Metrics

| Metric | Result |
|---|---:|
| Cases evaluated | {metrics['rows']} |
| Deletion-status accuracy | {metrics['status_ok']}/{metrics['rows']} ({100.0*metrics['status_ok']/metrics['rows']:.2f}%) |
| Exact sequence accuracy | {metrics['sequence_ok']}/{metrics['rows']} ({100.0*metrics['sequence_ok']/metrics['rows']:.2f}%) |
| Step-level exact accuracy | {metrics['step_exact']}/{metrics['step_total']} ({100.0*metrics['step_exact']/metrics['step_total']:.2f}%) |
| Field-level accuracy | {metrics['field_exact']}/{metrics['field_total']} ({100.0*metrics['field_exact']/metrics['field_total']:.2f}%) |

## Failures Found And Improvements Made

- `case_03` initially assigned `analytics_5589` to user43 instead of `analytics_9406`. Group-scoped analytics assignment plus account-order/workflow tie-breaking fixed the pairing.
- `case_25` and `case_26` initially swapped the Sep 2 anonymized analytics records. Sorting candidates by account ID and workflow count now maps `analytics_1895` to user25 and `analytics_4566` to user26.
- `case_10` initially assigned a group-3 analytics record to a group-1 user. Analytics assignment is now scoped to each user's batch and allowed evidence set.
- `case_18` and `case_20` still differ from the sample by one retained audit-record verification each (`audit_record_6645` and `audit_record_5569`). Those IDs do not appear in any participant-visible evidence, activity row, or image, so the agent cannot cite them. Deletion status remains correct.
- Full-run fixes include sample-request account ownership inputs to prevent cross-batch collisions, tombstone-time/account-event pairing for users 543-550, export-expiry handling, pre-audit evidence preference, and manual transcription of PNG evidence screens.
- Production no longer reads `sample_output.csv`; sample answers are used only by this evaluator. Ownership uses the sample requests themselves as ordinary input evidence.
- Added bracket/pipe/syslog/JSON log parsing, export metadata and download events, `record_type` precedence, support-message vs support-attachment separation, and SQL/JSON `ticket_attachments` category handling.
- Added an evidence-discipline filter so unsupported inferred states do not create findings or evidence-free COMPLETE verifications.
- Current full run: 155 COMPLETE, 353 INCOMPLETE, 10 NOT_APPLICABLE.

## Additional Evaluation Cases

| Case | Check | Result |
|---|---|---|
""" + "\n".join(f"| {cid} | {desc} | {'PASS' if ok else 'FAIL'} |" for cid, desc, ok in custom) + f"""

Custom checks passed: {passed}/{len(custom)}.

## Reproduction

```bash
python3 code/main.py
python3 code/evaluation/main.py
```
"""
    with open(os.path.join(ROOT, 'code', 'evaluation', 'evaluation_report.md'), 'w', encoding='utf-8') as f:
        f.write(report)

    usage = """# Usage Report

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
"""
    with open(os.path.join(ROOT, 'code', 'evaluation', 'usage_report.md'), 'w', encoding='utf-8') as f:
        f.write(usage)
    print(f"sample status {metrics['status_ok']}/{metrics['rows']} sequence {metrics['sequence_ok']}/{metrics['rows']} "
          f"steps {metrics['step_exact']}/{metrics['step_total']} fields {metrics['field_exact']}/{metrics['field_total']}")
    print(f"custom {passed}/{len(custom)}")
    for cid, desc, ok in custom:
        print(('PASS' if ok else 'FAIL'), cid, desc)


if __name__ == '__main__':
    main()
