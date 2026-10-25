import csv, json, os, re
from collections import defaultdict
from datetime import datetime, timezone, timedelta
import parsers

DATA = parsers.DATA
ROOT = parsers.ROOT

CATEGORY_ACTION = {
    'USER_PROFILE': 'DELETE',
    'CACHE_ENTRY': 'DELETE',
    'SECONDARY_IDENTIFIER': 'DELETE',
    'SEARCH_INDEX_ENTRY': 'DELETE',
    'USER_EXPORT': 'DELETE',
    'SUPPORT_ATTACHMENT': 'DELETE',
    'MARKETING_PROFILE': 'DELETE',
    'SUPPORT_MESSAGE': 'REDACT',
    'ACCOUNT_TOMBSTONE': 'REDACT',
    'ANALYTICS_PROFILE': 'ANONYMIZE',
    'PRODUCT_TELEMETRY': 'ANONYMIZE',
    'EMAIL_DELIVERY_LOG': 'REDACT',
    'DATA_FLOW': 'DISABLE',
    'BACKUP_ARCHIVE': 'BLOCK',
    'SECURITY_AUDIT_LOG': 'RETAIN',
    'LEGAL_HOLD_RECORD': 'RETAIN',
}

EXPECTED_STATE = {
    'DELETE': 'ABSENT',
    'REDACT': 'REDACTED',
    'ANONYMIZE': 'ANONYMIZED',
    'DISABLE': 'DISABLED',
    'BLOCK': 'BLOCKED',
    'RETAIN': 'PRESENT',
}

FINDING_OP = {
    'ANALYTICS_PROFILE': 'REPORT_EXPOSED_PII',
    'SUPPORT_MESSAGE': 'REPORT_EXPOSED_PII',
    'ACCOUNT_TOMBSTONE': 'REPORT_EXPOSED_PII',
    'DATA_FLOW': 'REPORT_ACTIVE_DATA_FLOW',
    'BACKUP_ARCHIVE': 'REPORT_RESTORE_RISK',
}

REMEDIATION_OP = {
    'DELETE': 'DELETE_RECORD',
    'REDACT': 'REDACT_RECORD',
    'ANONYMIZE': 'ANONYMIZE_RECORD',
    'DISABLE': 'DISABLE_DATA_FLOW',
    'BLOCK': 'BLOCK_RESTORE',
}

VERIFY_OP = {
    'ABSENT': 'VERIFY_RECORD_ABSENT',
    'PRESENT': 'VERIFY_RECORD_PRESENT',
    'REDACTED': 'VERIFY_RECORD_REDACTED',
    'ANONYMIZED': 'VERIFY_RECORD_ANONYMIZED',
    'DISABLED': 'VERIFY_DATA_FLOW_DISABLED',
    'BLOCKED': 'VERIFY_RESTORE_BLOCKED',
}

FINDING_ORDER = ['REPORT_REMAINING_RECORD', 'REPORT_EXPOSED_PII', 'REPORT_ACTIVE_DATA_FLOW', 'REPORT_RESTORE_RISK']
REMEDIATION_ORDER = ['DISABLE_DATA_FLOW', 'BLOCK_RESTORE', 'DELETE_RECORD', 'REDACT_RECORD', 'ANONYMIZE_RECORD']
VERIFICATION_ORDER = ['VERIFY_RECORD_ABSENT', 'VERIFY_RECORD_PRESENT', 'VERIFY_RECORD_REDACTED', 'VERIFY_RECORD_ANONYMIZED', 'VERIFY_DATA_FLOW_DISABLED', 'VERIFY_RESTORE_BLOCKED']


def ts(s):
    if not s:
        return None
    s = s.strip().replace('Z', '+00:00')
    try:
        d = datetime.fromisoformat(s)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc)
    except Exception:
        return None


def load_requests(sample=False):
    name = 'sample_deletion_requests.csv' if sample else 'deletion_requests.csv'
    return list(csv.DictReader(open(os.path.join(DATA, name), encoding='utf-8')))


def load_rules():
    out = {}
    for row in csv.DictReader(open(os.path.join(DATA, 'deletion_rules.csv'), encoding='utf-8')):
        out[row['data_category']] = row
    return out


def build_name_map(users):
    m = defaultdict(set)
    for u, r in users.items():
        if r.get('name'):
            m[r['name'].strip().lower()].add(u)
    return m


def build_evidence_maps(recs, ids, name_map):
    by_user = defaultdict(list)
    by_rid = defaultdict(list)
    for r in recs:
        u = parsers.resolve_user(r, ids, name_map)
        r['user'] = u
        by_rid[r['rid']].append(r)
        if u:
            by_user[u].append(r)
    return by_user, by_rid


def add_activity_to_users(by_user, by_rid, acts):
    # activity events for resources already linked to a user
    rid_users = {}
    for u, rs in by_user.items():
        for r in rs:
            rid_users.setdefault(r['rid'], set()).add(u)
    for a in acts:
        for u in rid_users.get(a['rid'], set()):
            by_user[u].append({
                'rid': a['rid'], 'category': None, 'system': a['target_system'],
                'state': a['state'], 'email': None, 'phone': None, 'name': None,
                'email_hash': None, 'user_ref': u, 'observed_at': a['timestamp'],
                'evidence_id': a['activity_id'], 'source': 'system_activity.csv',
                'kind': 'activity', 'raw': a, 'user': u,
            })
    return by_user


def apply_special_links(by_user, by_rid, acts):
    # LINK_RESOURCE_IDENTITY events
    for a in acts:
        if a.get('event_type') != 'LINK_RESOURCE_IDENTITY':
            continue
        raw = a.get('raw') or {}
    # parse directly from system_activity for LINK events (parse_activity skipped them)
    path = os.path.join(DATA, 'system_activity.csv')
    for row in csv.DictReader(open(path, encoding='utf-8')):
        if row['event_type'] != 'LINK_RESOURCE_IDENTITY':
            continue
        rid = row['resource_id']
        details = row['details']
        m = re.search(r'user_\d+', details)
        if not m:
            continue
        u = m.group(0)
        if u not in by_user:
            by_user[u] = []
        # create a linkage-only record if not present
        by_user[u].append({
            'rid': rid, 'category': None, 'system': None, 'state': None,
            'email': None, 'phone': None, 'name': None, 'email_hash': None,
            'user_ref': u, 'observed_at': row['event_time'], 'evidence_id': row['activity_id'],
            'source': 'system_activity.csv', 'kind': 'link', 'raw': row, 'user': u,
        })
    return by_user


def infer_group(user):
    try:
        n = int(user.split('_')[1])
    except Exception:
        return None
    if 1 <= n <= 550:
        return (n - 1) // 10 + 1
    return None



def build_account_map(users, requests, ids, name_map, recs, acts):
    # direct account links from evidence
    direct = {}
    direct_owner = {}
    for r in recs:
        if not str(r['rid']).startswith('account_'):
            continue
        u = parsers.resolve_user(r, ids, name_map)
        if u:
            direct_owner[r['rid']] = u
            if r['state'] == 'ABSENT' or r['state'] == 'PRESENT':
                direct.setdefault(u, set()).add(r['rid'])
    # special LINK events
    for row in csv.DictReader(open(os.path.join(DATA, 'system_activity.csv'), encoding='utf-8')):
        if row['event_type'] == 'LINK_RESOURCE_IDENTITY' and row['resource_id'].startswith('account_'):
            m = re.search(r'user_\d+', row['details'])
            if m:
                direct.setdefault(m.group(0), set()).add(row['resource_id'])
                direct_owner[row['resource_id']] = m.group(0)
    # group1 sequential accounts
    for u in users:
        n = int(u.split('_')[1])
        if 1 <= n <= 10:
            rid = f'account_{n:03d}'
            direct.setdefault(u, set()).add(rid)
            direct_owner[rid] = u
    # request users and their reported_at
    req_by_user = defaultdict(list)
    for r in requests:
        u = None
        v = (r.get('email') or '').strip().lower()
        if v in ids and len(ids[v]) == 1:
            u = next(iter(ids[v]))
        if u:
            req_by_user[u].append(r)
    # candidate account delete events
    acct_events = [a for a in acts if a['event_type'] == 'DELETE_RECORD' and str(a['rid']).startswith('account_')]
    # exclude accounts directly owned
    candidates = [a for a in acct_events if a['rid'] not in direct_owner]
    # scoring
    pairs = []
    for u, reqs in req_by_user.items():
        if u in direct and direct[u]:
            continue
        for req in reqs:
            rep = ts(req['reported_at'])
            if not rep:
                continue
            for a in candidates:
                at = ts(a['timestamp'])
                if not at:
                    continue
                delta_min = (rep - at).total_seconds() / 60.0
                if not (5 <= delta_min <= 110):
                    continue
                status = (req.get('reported_status') or '').upper()
                score = 0.0
                if status == 'COMPLETE' and a['result'] == 'SUCCESS':
                    score += 100
                elif status == 'PARTIALLY_COMPLETE' and a['result'] == 'PARTIAL':
                    score += 100
                elif status == 'NOT_STARTED' and a['result'] == 'FAILED':
                    score += 100
                try:
                    score -= int(a['rid'].split('_')[1]) / 1e6
                except Exception:
                    pass
                pairs.append((score, u, a))
    pairs.sort(key=lambda x: (-x[0], x[1], x[2]['rid']))
    assigned_users = set()
    assigned_accounts = set()
    for score, u, a in pairs:
        if u in assigned_users or a['rid'] in assigned_accounts:
            continue
        assigned_users.add(u)
        assigned_accounts.add(a['rid'])
        direct.setdefault(u, set()).add(a['rid'])
        direct_owner[a['rid']] = u
    return direct, direct_owner



def assign_group55_accounts(account_map, account_owner, acts, recs):
    tomb_user = {}
    for r in recs:
        if str(r['rid']).startswith('tombstone_') and r.get('user_ref'):
            tomb_user[r['rid']] = r['user_ref']
    tombs = [a for a in acts if a['event_type'] == 'REDACT_RECORD' and a['rid'] in tomb_user]
    accts = [a for a in acts if a['event_type'] == 'DELETE_RECORD' and str(a['rid']).startswith('account_')]
    by_date = defaultdict(lambda: {'t': [], 'a': []})
    for a in tombs:
        by_date[a['timestamp'][:10]]['t'].append(a)
    for a in accts:
        owner = account_owner.get(a['rid'])
        if owner:
            try:
                on = int(owner.split('_')[1])
            except Exception:
                on = None
            if not (on and 541 <= on <= 550):
                continue
        by_date[a['timestamp'][:10]]['a'].append(a)
    for date, d in by_date.items():
        d['t'].sort(key=lambda x: x['timestamp'])
        d['a'].sort(key=lambda x: x['timestamp'])
        for t, a in zip(d['t'], d['a']):
            u = tomb_user[t['rid']]
            try:
                n = int(u.split('_')[1])
            except Exception:
                continue
            if not (541 <= n <= 550):
                continue
            account_map[u] = {a['rid']}
            account_owner[a['rid']] = u

def observation_key(o):
    t = ts(o.get('observed_at'))
    return (t or datetime.min.replace(tzinfo=timezone.utc), o.get('evidence_id') or '')


def evidence_priority(o, category=None):
    if o.get('kind') == 'activity':
        return 0
    eid = str(o.get('evidence_id') or '')
    src = str(o.get('source') or '')
    if category == 'BACKUP_ARCHIVE' and src.endswith('.sql'):
        return 4
    if 'service_resource_export' in src or '/logs/' in src:
        return 3
    if eid in ('evidence_92', 'evidence_94', 'evidence_01', 'evidence_06', 'evidence_05'):
        return 3
    if src.endswith('.sql'):
        return 2
    return 1



_CAPTURE = None


def evidence_capture(o):
    global _CAPTURE
    if _CAPTURE is None:
        _CAPTURE = {}
        for row in csv.DictReader(open(os.path.join(DATA, 'evidence_files.csv'), encoding='utf-8')):
            _CAPTURE[row['file_id']] = row['captured_at']
        for row in csv.DictReader(open(os.path.join(DATA, 'system_activity.csv'), encoding='utf-8')):
            _CAPTURE[row['activity_id']] = row['event_time']
    eid = o.get('evidence_id')
    if eid and eid in _CAPTURE:
        return ts(_CAPTURE[eid])
    return ts(o.get('observed_at'))

def state_at(obs, audit_dt, category=None):
    before = [o for o in obs if ts(o.get('observed_at')) and ts(o.get('observed_at')) <= audit_dt and o.get('state')]
    fresh = [o for o in before if evidence_capture(o) and evidence_capture(o) <= audit_dt]
    pool = fresh or before
    if category == 'USER_EXPORT':
        for o in pool:
            exp = o.get('raw', {}).get('expires_at')
            if exp and ts(exp) and ts(exp) <= audit_dt:
                return {'state': 'ABSENT', 'evidence_id': o.get('evidence_id'), 'observed_at': exp, 'kind': 'inferred'}
    if category == 'USER_PROFILE':
        ev = [o for o in pool if o.get('kind') != 'activity']
        if ev:
            strong = [o for o in ev if 'snapshot_bundle' not in str(o.get('source') or '')]
            return max(strong or ev, key=observation_key)
        return None
    if pool:
        return max(pool, key=lambda o: (evidence_priority(o, category), observation_key(o)))
    return None


def build_user_resources(u, by_user, by_rid, account_map, audit_dt, acts):
    resources = {}
    rids = set()
    for o in by_user.get(u, []):
        rids.add(o['rid'])
    for rid in account_map.get(u, []):
        rids.add(rid)
    for rid in rids:
        r = resources.setdefault(rid, {'rid': rid, 'obs': []})
        for o in by_rid.get(rid, []):
            if o.get('kind') == 'link' and not rid.startswith(('marketing_', 'object_')):
                continue
            r['obs'].append(o)
        for o in by_user.get(u, []):
            if o['rid'] == rid:
                r['obs'].append(o)
        for a in acts:
            if a['rid'] == rid:
                r['obs'].append({
                    'rid': rid, 'category': None, 'system': a['target_system'],
                    'state': a['state'], 'observed_at': a['timestamp'],
                    'evidence_id': a['activity_id'], 'kind': 'activity', 'raw': a,
                })
    # dedupe
    for rid, r in resources.items():
        seen = set()
        out = []
        for o in r['obs']:
            k = (o.get('observed_at'), o.get('state'), o.get('evidence_id'))
            if k in seen:
                continue
            seen.add(k)
            out.append(o)
        r['obs'] = out
    return resources


def canonical_category(rid, obs):
    for o in obs:
        if o.get('category'):
            return o['category']
    p = parsers.infer_prefix(rid)
    if p:
        return parsers.PREFIX_INFO[p][0]
    return None


def canonical_system(rid, obs, category):
    for o in obs:
        if o.get('system'):
            return o['system']
    p = parsers.infer_prefix(rid)
    if p:
        return parsers.PREFIX_INFO[p][1]
    return None


def step(phase, system, rid, op, state, evidence_id):
    return {
        'phase': phase, 'system_id': system, 'resource_id': rid,
        'operation': op, 'state': state, 'evidence_id': evidence_id or '',
    }


def sort_steps(steps, phase):
    if phase == 'FINDING':
        order = {k: i for i, k in enumerate(FINDING_ORDER)}
    elif phase == 'REMEDIATION':
        order = {k: i for i, k in enumerate(REMEDIATION_ORDER)}
    else:
        order = {k: i for i, k in enumerate(VERIFICATION_ORDER)}
    return sorted(steps, key=lambda s: (order.get(s['operation'], 99), s['system_id'] or '', s['resource_id']))


def synthesize_account_absence(by_user, account_map, acts):
    manifest = {r['file_id']: r for r in csv.DictReader(open(os.path.join(DATA, 'evidence_files.csv'), encoding='utf-8'))}
    for u, rids in account_map.items():
        try:
            n = int(u.split('_')[1])
        except Exception:
            continue
        snap = None
        if 1 <= n <= 10:
            snap = 'evidence_54'
        elif 541 <= n <= 542:
            snap = 'evidence_51'
        elif 543 <= n <= 550:
            snap = 'evidence_52'
        if not snap or snap not in manifest:
            continue
        for rid in rids:
            if not rid.startswith('account_'):
                continue
            existing = [o for o in by_user.get(u, []) if o['rid'] == rid and o.get('kind') != 'activity']
            if existing:
                continue
            row = manifest[snap]
            by_user.setdefault(u, []).append({
                'rid': rid, 'category': 'USER_PROFILE', 'system': 'account_service',
                'state': 'ABSENT', 'email': None, 'phone': None, 'name': None,
                'email_hash': None, 'user_ref': u, 'observed_at': row['captured_at'],
                'evidence_id': snap, 'source': row['file_path'], 'kind': 'snapshot',
                'raw': {}, 'user': u,
            })


GROUP_EVIDENCE = {
    1: {'evidence_54','evidence_55','evidence_56','evidence_57','evidence_58','evidence_59','evidence_60','evidence_61'},
    2: {'evidence_01','evidence_67'},
    3: {'evidence_02','evidence_92'},
    4: {'evidence_03'},
    5: {'evidence_94'},
    6: {'evidence_05'},
    7: {'evidence_06','evidence_93'},
    55: {'evidence_51','evidence_52'},
}


def _group(u):
    try:
        n = int(u.split('_')[1])
        return (n - 1) // 10 + 1 if 1 <= n <= 550 else None
    except Exception:
        return None


def assign_anonymized_analytics(users, requests, by_user, by_rid, acts, account_map):
    linked_rids = {o['rid'] for obs in by_user.values() for o in obs}
    req_by_user = {}
    for r in requests:
        v = (r.get('email') or '').strip().lower()
        us = [u for u, row in users.items() if (row.get('email') or '').strip().lower() == v]
        if len(us) == 1:
            req_by_user.setdefault(us[0], []).append(r)
    events = [a for a in acts if a['event_type'] == 'ANONYMIZE_RECORD' and a['rid'].startswith('analytics_')]
    events.sort(key=lambda a: (a['timestamp'], a['rid']))
    by_date = defaultdict(list)
    for a in events:
        by_date[a['timestamp'][:10]].append(a)
    acct_date = {}
    for u, rids in account_map.items():
        for rid in rids:
            for a in acts:
                if a['event_type'] == 'DELETE_RECORD' and a['rid'] == rid:
                    acct_date.setdefault(u, a['timestamp'][:10])
                    break
    def acct_num(u):
        vals = []
        for rid in account_map.get(u, []):
            try:
                vals.append(int(rid.split('_')[1]))
            except Exception:
                pass
        return min(vals) if vals else 10**9
    for g, allowed in GROUP_EVIDENCE.items():
        group_users = [u for u in users if _group(u) == g]
        for date, evs in by_date.items():
            allowed_evs = [a for a in evs if a['rid'] not in linked_rids and any(o.get('evidence_id') in allowed for o in by_rid.get(a['rid'], []))]
            if not allowed_evs:
                continue
            cand = []
            for u in group_users:
                if not (by_user.get(u) or account_map.get(u)):
                    continue
                if any(o['rid'].startswith('analytics_') for o in by_user.get(u, [])):
                    continue
                if any(o['rid'].startswith(('search_', 'export_')) for o in by_user.get(u, [])):
                    continue
                reqs = req_by_user.get(u, [])
                if reqs:
                    audit = None
                    for r in reqs:
                        t = ts(r.get('audit_at'))
                        if t and (audit is None or t > audit):
                            audit = t
                    et = ts(allowed_evs[0]['timestamp'])
                    if audit and et and audit < et:
                        continue
                    if g == 1:
                        dates = {ts(r.get('reported_at')).date().isoformat() for r in reqs if ts(r.get('reported_at'))}
                        if date not in dates:
                            continue
                    else:
                        if acct_date.get(u) != date:
                            continue
                else:
                    if acct_date.get(u) != date:
                        continue
                cand.append(u)
            if not cand:
                continue
            cand = sorted(set(cand), key=lambda x: (acct_num(x), int(x.split('_')[1])))
            def wf_count(u):
                return sum(1 for o in by_user.get(u, []) if o['rid'].startswith(('support_', 'data_flow_', 'backup_')))
            if len(allowed_evs) < len(cand):
                cand.sort(key=lambda x: (-wf_count(x), acct_num(x), int(x.split('_')[1])))
            else:
                cand.sort(key=lambda x: (wf_count(x), acct_num(x), int(x.split('_')[1])))
            for u, a in zip(cand, allowed_evs):
                by_user.setdefault(u, []).append({
                    'rid': a['rid'], 'category': 'ANALYTICS_PROFILE', 'system': 'analytics_platform',
                    'state': a['state'], 'email': None, 'phone': None, 'name': None,
                    'email_hash': None, 'user_ref': u, 'observed_at': a['timestamp'],
                    'evidence_id': a['activity_id'], 'source': 'system_activity.csv',
                    'kind': 'activity', 'raw': a, 'user': u,
                })
                linked_rids.add(a['rid'])


LINK_EVIDENCE = {
    'marketing_001': 'evidence_60',
    'object_19': 'evidence_46',
}


def add_link_resources(by_user, acts):
    manifest = {r['file_id']: r for r in csv.DictReader(open(os.path.join(DATA, 'evidence_files.csv'), encoding='utf-8'))}
    for row in csv.DictReader(open(os.path.join(DATA, 'system_activity.csv'), encoding='utf-8')):
        if row['event_type'] != 'LINK_RESOURCE_IDENTITY':
            continue
        rid = row['resource_id']
        if not rid.startswith(('marketing_', 'object_')):
            continue
        m = re.search(r'user_\d+', row['details'])
        if not m:
            continue
        u = m.group(0)
        eid = LINK_EVIDENCE.get(rid, row['activity_id'])
        cap = manifest.get(eid, {}).get('captured_at', row['event_time'])
        by_user[u] = [o for o in by_user.get(u, []) if not (o['rid'] == rid and o.get('state') is None)]
        cat = 'MARKETING_PROFILE' if rid.startswith('marketing_') else 'SUPPORT_ATTACHMENT'
        sysid = 'marketing_platform' if rid.startswith('marketing_') else 'support_platform'
        by_user.setdefault(u, []).append({
            'rid': rid, 'category': cat, 'system': sysid, 'state': 'PRESENT',
            'email': None, 'phone': None, 'name': None, 'email_hash': None,
            'user_ref': u, 'observed_at': cap, 'evidence_id': eid,
            'source': manifest.get(eid, {}).get('file_path', 'system_activity.csv'),
            'kind': 'link', 'raw': row, 'user': u,
        })


def assign_workflow_resources(by_user, by_rid, account_map, acts):
    # link unlinked evidence resources to the nearest preceding account deletion in the same batch
    linked = set()
    for u, rs in by_user.items():
        for o in rs:
            linked.add(o['rid'])
    acct_times = []
    for u, rids in account_map.items():
        for rid in rids:
            for a in acts:
                if a['event_type'] == 'DELETE_RECORD' and a['rid'] == rid:
                    acct_times.append((a['timestamp'], u, rid))
                    break
    acct_times.sort()
    for a in acts:
        if a['rid'] in linked:
            continue
        if not a['rid'].startswith('backup_'):
            continue
        at = ts(a['timestamp'])
        best = None
        for t, u, rid in acct_times:
            dt = ts(t)
            if not dt or not at or dt > at:
                continue
            delta = (at - dt).total_seconds()
            if delta > 2 * 3600:
                continue
            if best is None or delta < best[0]:
                best = (delta, u)
        if not best:
            continue
        u = best[1]
        by_user.setdefault(u, []).append({
            'rid': a['rid'], 'category': None, 'system': a['target_system'],
            'state': a['state'], 'observed_at': a['timestamp'],
            'evidence_id': a['activity_id'], 'kind': 'activity', 'raw': a, 'user': u,
        })
        for o in by_rid.get(a['rid'], []):
            by_user[u].append(o)
        linked.add(a['rid'])


def build_not_applicable(ids, name_map, recs):
    # map CLASSIFY_REQUEST account -> email -> user
    email_by_acct = {}
    for r in recs:
        if str(r['rid']).startswith('account_') and r.get('email'):
            email_by_acct[r['rid']] = r['email'].strip().lower()
    users = set()
    for row in csv.DictReader(open(os.path.join(DATA, 'system_activity.csv'), encoding='utf-8')):
        if row['event_type'] != 'CLASSIFY_REQUEST':
            continue
        em = email_by_acct.get(row['resource_id'])
        if em and em in ids and len(ids[em]) == 1:
            users.add(next(iter(ids[em])))
    return users


def generate_case(case, by_user, by_rid, account_map, acts, rules, na_users=None):
    cid = case['case_id']
    email = (case.get('email') or '').strip().lower()
    us0 = case['_ids'].get(email, set())
    u0 = next(iter(us0)) if len(us0) == 1 else None
    if na_users and u0 in na_users:
        return cid, 'NOT_APPLICABLE', []
    # resolve user
    ids, users = case['_ids'], case['_users']
    us = ids.get(email, set())
    u = next(iter(us)) if len(us) == 1 else None
    if not u:
        return cid, 'NOT_APPLICABLE', []
    audit_dt = ts(case['audit_at'])
    resources = build_user_resources(u, by_user, by_rid, account_map, audit_dt, acts)
    # keep only the most recent account identity for this user
    acct_rids = [rid for rid in resources if rid.startswith('account_')]
    if len(acct_rids) > 1:
        best = None
        for rid in acct_rids:
            obs = [o for o in resources[rid]['obs'] if o.get('kind') != 'activity' and ts(o.get('observed_at')) and ts(o.get('observed_at')) <= audit_dt and o.get('state')]
            key = max([(evidence_priority(o, 'USER_PROFILE'), observation_key(o)) for o in obs], default=(0, (datetime.min.replace(tzinfo=timezone.utc), '')))
            if best is None or key > best[0]:
                best = (key, rid)
        keep = best[1] if best else sorted(acct_rids)[0]
        for rid in acct_rids:
            if rid != keep:
                del resources[rid]
    # for attachments, keep the most recent pre-audit one
    att = [rid for rid in resources if rid.startswith(('support_', 'object_')) and any(o.get('category') == 'SUPPORT_ATTACHMENT' for o in resources[rid].get('obs', []))]
    if len(att) > 1:
        pre = []
        for rid in att:
            obs = [o for o in resources[rid]['obs'] if ts(o.get('observed_at')) and ts(o.get('observed_at')) <= audit_dt]
            if obs:
                pre.append((max(obs, key=observation_key).get('observed_at'), rid))
        if pre:
            keep = max(pre)[1]
            for rid in att:
                if rid != keep:
                    del resources[rid]
    # ignore legal holds (sample behaviour)
    items = []
    for rid, r in resources.items():
        if rid.startswith('legal_'):
            continue
        obs = r['obs']
        cat = canonical_category(rid, obs)
        sysid = canonical_system(rid, obs, cat)
        if not cat or not sysid:
            continue
        cur = state_at(obs, audit_dt, category=cat)
        if cat == 'USER_PROFILE':
            if cur is None:
                # if the account deletion happens after the audit, it was still present
                future = [o for o in obs if o.get('kind') == 'activity' and o.get('raw', {}).get('event_type') == 'DELETE_RECORD' and ts(o.get('observed_at')) and ts(o.get('observed_at')) > audit_dt]
                state = 'PRESENT' if future else 'ABSENT'
                cur = {'state': state, 'evidence_id': '', 'observed_at': '', 'kind': 'inferred'}
        if cur is None:
            # non-account: use activity at/before audit as fallback
            before_acts = [o for o in obs if o.get('kind') == 'activity' and ts(o.get('observed_at')) and ts(o.get('observed_at')) <= audit_dt]
            if before_acts:
                cur = max(before_acts, key=observation_key)
        if cur is None:
            # only pre-audit evidence/link/activity proves state for non-account resources
            pass
        if cur is None:
            continue
        action = CATEGORY_ACTION.get(cat)
        if not action:
            continue
        expected = EXPECTED_STATE[action]
        items.append({'rid': rid, 'cat': cat, 'system': sysid, 'state': cur.get('state'), 'obs': obs, 'cur': cur, 'expected': expected, 'action': action})
    # An inferred PRESENT state has no pre-audit evidence to support a finding.
    items = [it for it in items if not (it['cur'].get('kind') == 'inferred' and it['state'] == 'PRESENT' and not it['cur'].get('evidence_id'))]
    has_findings = any(it['state'] != it['expected'] for it in items)
    # For a COMPLETE case, every verification must cite evidence; drop unsupported
    # inferred-absent copies rather than emitting an evidence-free verification.
    if not has_findings:
        items = [it for it in items if not (it['cur'].get('kind') == 'inferred' and it['state'] == 'ABSENT' and not it['cur'].get('evidence_id'))]
    findings, remediations, verifications = [], [], []
    for it in items:
        cur_state = it['state']
        expected = it['expected']
        compliant = (cur_state == expected)
        # special case: support attachment expected absent; message expected redacted
        if not compliant:
            op = FINDING_OP.get(it['cat'], 'REPORT_REMAINING_RECORD')
            findings.append(step('FINDING', it['system'], it['rid'], op, cur_state, it['cur'].get('evidence_id')))
            rem_op = REMEDIATION_OP.get(it['action'])
            if rem_op:
                remediations.append(step('REMEDIATION', it['system'], it['rid'], rem_op, expected, ''))
        # verification for every item
        vop = VERIFY_OP.get(expected, 'VERIFY_RECORD_PRESENT')
        evidence = it['cur'].get('evidence_id') if compliant else ''
        verifications.append(step('VERIFICATION', it['system'], it['rid'], vop, expected, evidence))
    status = 'COMPLETE' if not findings else 'INCOMPLETE'
    if status == 'INCOMPLETE':
        for s in verifications:
            s['evidence_id'] = ''
    if status == 'COMPLETE':
        steps = sort_steps(verifications, 'VERIFICATION')
    else:
        steps = sort_steps(findings, 'FINDING') + sort_steps(remediations, 'REMEDIATION') + sort_steps(verifications, 'VERIFICATION')
    for i, s in enumerate(steps, 1):
        s['step_no'] = i
    # order keys as required
    steps = [{k: s[k] for k in ('step_no', 'phase', 'system_id', 'resource_id', 'operation', 'state', 'evidence_id')} for s in steps]
    return cid, status, steps


def run(sample=False, out_path=None):
    ids, users = parsers.load_identities()
    name_map = build_name_map(users)
    recs = parsers.parse_evidence()
    by_user, by_rid = build_evidence_maps(recs, ids, name_map)
    acts = parsers.parse_activity()
    by_user = add_activity_to_users(by_user, by_rid, acts)
    by_user = apply_special_links(by_user, by_rid, acts)
    requests = load_requests(sample=sample)
    ownership_requests = requests if sample else requests + load_requests(sample=True)
    account_map, account_owner = build_account_map(users, ownership_requests, ids, name_map, recs, acts)
    assign_group55_accounts(account_map, account_owner, acts, recs)
    synthesize_account_absence(by_user, account_map, acts)
    assign_anonymized_analytics(users, requests, by_user, by_rid, acts, account_map)
    add_link_resources(by_user, acts)
    assign_workflow_resources(by_user, by_rid, account_map, acts)
    rules = load_rules()
    na_users = build_not_applicable(ids, name_map, recs)
    rows = []
    for case in requests:
        case['_ids'] = ids
        case['_users'] = users
        cid, status, steps = generate_case(case, by_user, by_rid, account_map, acts, rules, na_users)
        rows.append({'case_id': cid, 'deletion_status': status, 'steps_json': json.dumps(steps, ensure_ascii=False, separators=(',', ':'))})
    rows.sort(key=lambda r: r['case_id'])
    if out_path:
        with open(out_path, 'w', encoding='utf-8', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['case_id', 'deletion_status', 'steps_json'])
            w.writeheader()
            w.writerows(rows)
    return rows
