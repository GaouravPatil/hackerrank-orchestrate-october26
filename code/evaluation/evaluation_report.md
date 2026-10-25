# Evaluation Report

## Method

The evaluator runs the production pipeline in `code/engine.py` directly, compares the 32 public sample cases against `dataset/sample_output.csv`, then applies six additional evidence-derived checks to the 518-case full run. Comparison is structural: phase order, step order, resource IDs, operations, states, and evidence references must all match.

## Sample Metrics

| Metric | Result |
|---|---:|
| Cases evaluated | 32 |
| Deletion-status accuracy | 32/32 (100.00%) |
| Exact sequence accuracy | 30/32 (93.75%) |
| Step-level exact accuracy | 187/193 (96.89%) |
| Field-level accuracy | 1321/1351 (97.78%) |

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
| case_538 | marketing opt-out is not a deletion request | PASS |
| case_544 | failed tombstone redaction is incomplete and reports exposed PII | PASS |
| case_543 | successful tombstone redaction is complete | PASS |
| case_99 | restorable backup is reported as a restore risk | PASS |
| case_63 | catalog-linked marketing profile is a remaining record | PASS |
| case_45 | retained security audit record is verified present | PASS |

Custom checks passed: 6/6.

## Reproduction

```bash
python3 code/main.py
python3 code/evaluation/main.py
```
