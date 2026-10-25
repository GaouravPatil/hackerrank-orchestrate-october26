import csv, json, os, re, sqlite3, subprocess, hashlib
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, 'dataset')

PREFIX_INFO = {
    'account': ('USER_PROFILE', 'account_service'),
    'search': ('SEARCH_INDEX_ENTRY', 'search_service'),
    'analytics': ('ANALYTICS_PROFILE', 'analytics_platform'),
    'support': ('SUPPORT_MESSAGE', 'support_platform'),
    'data_flow': ('DATA_FLOW', 'integration_service'),
    'backup': ('BACKUP_ARCHIVE', 'backup_service'),
    'audit_record': ('SECURITY_AUDIT_LOG', 'security_service'),
    'tombstone': ('ACCOUNT_TOMBSTONE', 'identity_service'),
    'export': ('USER_EXPORT', 'export_service'),
    'marketing': ('MARKETING_PROFILE', 'marketing_platform'),
    'object': ('SUPPORT_ATTACHMENT', 'support_platform'),
    'legal': ('LEGAL_HOLD_RECORD', 'legal_service'),
    'email_delivery': ('EMAIL_DELIVERY_LOG', 'email_service'),
    'cache': ('CACHE_ENTRY', 'cache_service'),
    'product_telemetry': ('PRODUCT_TELEMETRY', 'telemetry_service'),
}

TYPE_INFO = {
    'USER_PROFILE': ('USER_PROFILE', 'account_service'),
    'SECONDARY_IDENTIFIER': ('SECONDARY_IDENTIFIER', 'identity_service'),
    'SEARCH_INDEX_ENTRY': ('SEARCH_INDEX_ENTRY', 'search_service'),
    'CACHE_ENTRY': ('CACHE_ENTRY', 'cache_service'),
    'USER_EXPORT': ('USER_EXPORT', 'export_service'),
    'MARKETING_PROFILE': ('MARKETING_PROFILE', 'marketing_platform'),
    'SUPPORT_MESSAGE': ('SUPPORT_MESSAGE', 'support_platform'),
    'SUPPORT_ATTACHMENT': ('SUPPORT_ATTACHMENT', 'support_platform'),
    'ANALYTICS_PROFILE': ('ANALYTICS_PROFILE', 'analytics_platform'),
    'PRODUCT_TELEMETRY': ('PRODUCT_TELEMETRY', 'telemetry_service'),
    'EMAIL_DELIVERY_LOG': ('EMAIL_DELIVERY_LOG', 'email_service'),
    'SECURITY_AUDIT_LOG': ('SECURITY_AUDIT_LOG', 'security_service'),
    'LEGAL_HOLD_RECORD': ('LEGAL_HOLD_RECORD', 'legal_service'),
    'BACKUP_ARCHIVE': ('BACKUP_ARCHIVE', 'backup_service'),
    'ACCOUNT_TOMBSTONE': ('ACCOUNT_TOMBSTONE', 'identity_service'),
    'DATA_FLOW': ('DATA_FLOW', 'integration_service'),
}

SYSTEM_ALIASES = {
    'account_service': 'account_service',
    'search_service': 'search_service',
    'analytics_platform': 'analytics_platform',
    'support_platform': 'support_platform',
    'integration_service': 'integration_service',
    'backup_service': 'backup_service',
    'security_service': 'security_service',
    'identity_service': 'identity_service',
    'export_service': 'export_service',
    'email_service': 'email_service',
    'cache_service': 'cache_service',
    'legal_service': 'legal_service',
    'marketing_platform': 'marketing_platform',
}

EMAIL_RE = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
PHONE_RE = re.compile(r'\+?\d[\d ()\-]{6,}\d')
RID_RE = re.compile(r'\b(account|search|analytics|support|data_flow|backup|audit_record|tombstone|export|marketing|object|legal|email_delivery|cache|product_telemetry)_[A-Za-z0-9]+\b')


def norm_email(s):
    return s.strip().lower() if isinstance(s, str) else None


def infer_prefix(rid):
    if not rid or not isinstance(rid, str):
        return None
    for p in sorted(PREFIX_INFO, key=len, reverse=True):
        if rid.startswith(p + '_'):
            return p
    return None


def info_for(rid, record_type=None, system=None):
    if record_type in TYPE_INFO:
        cat, sysid = TYPE_INFO[record_type]
    else:
        p = infer_prefix(rid)
        if p:
            cat, sysid = PREFIX_INFO[p]
        else:
            cat, sysid = None, None
    if system in SYSTEM_ALIASES:
        sysid = SYSTEM_ALIASES[system]
    return cat, sysid


def pick_state(d, category, rid):
    for key in ('state', 'status', 'result'):
        v = d.get(key)
        if isinstance(v, str):
            u = v.strip().upper().replace('-', '_').replace(' ', '_')
            mp = {
                'FOUND': 'PRESENT', 'NOT_FOUND': 'ABSENT', 'IDENTIFIABLE': 'PRESENT',
                'PRESENT': 'PRESENT', 'ABSENT': 'ABSENT', 'REDACTED': 'REDACTED',
                'ANONYMIZED': 'ANONYMIZED', 'DISABLED': 'DISABLED', 'BLOCKED': 'BLOCKED',
                'ACTIVE': 'ACTIVE', 'DELETED': 'ABSENT', 'DELETION_PENDING': 'PRESENT',
            }
            if u in mp:
                return mp[u]
    sc = d.get('status_code', d.get('http_status'))
    if sc is not None:
        try:
            sc = int(sc)
            if sc == 404:
                return 'ABSENT'
            if 200 <= sc < 300:
                return 'PRESENT'
        except Exception:
            pass
    if 'profile' in d:
        return 'ABSENT' if d.get('profile') is None else 'PRESENT'
    if 'rows' in d:
        try:
            return 'ABSENT' if int(d.get('rows')) == 0 else 'PRESENT'
        except Exception:
            pass
    if category == 'ANALYTICS_PROFILE':
        if any(d.get(k) for k in ('user_id', 'email', 'phone', 'email_hash', 'customer_reference', 'matched_value')):
            return 'PRESENT'
        return 'ANONYMIZED'
    if category == 'ACCOUNT_TOMBSTONE':
        if any(d.get(k) for k in ('name', 'email', 'phone', 'email_hash', 'full_name')):
            return 'PRESENT'
        return 'REDACTED'
    if category == 'SUPPORT_MESSAGE':
        mt = d.get('message_text') or d.get('message_excerpt') or d.get('message')
        pii = any(d.get(k) for k in ('requester_name', 'requester_email', 'requester_phone', 'email', 'phone', 'name', 'matched_value'))
        if mt and '[REDACTED]' in str(mt) and not pii:
            return 'REDACTED'
        return 'PRESENT' if (pii or (mt and EMAIL_RE.search(str(mt)))) else 'REDACTED'
    if category == 'SUPPORT_ATTACHMENT':
        return 'PRESENT'
    if category == 'DATA_FLOW':
        if 'enabled' in d:
            return 'ACTIVE' if str(d.get('enabled')).lower() in ('1', 'true', 'yes') else 'DISABLED'
    if category == 'BACKUP_ARCHIVE':
        if 'restore_allowed' in d:
            return 'ACTIVE' if str(d.get('restore_allowed')).lower() in ('1', 'true', 'yes') else 'BLOCKED'
        if 'eligible' in d:
            if str(d.get('deletion_block')).lower() in ('1', 'true', 'yes'):
                return 'BLOCKED'
            return 'ACTIVE' if str(d.get('eligible')).lower() in ('1', 'true', 'yes') else 'BLOCKED'
    if category == 'SECURITY_AUDIT_LOG':
        return 'PRESENT'
    if category == 'USER_PROFILE':
        st = d.get('account_status')
        if st:
            return 'ABSENT' if str(st).upper() == 'DELETED' else 'PRESENT'
        return 'PRESENT'
    if category == 'CACHE_ENTRY':
        if 'rows' in d:
            try:
                return 'PRESENT' if int(d.get('rows')) > 0 else 'ABSENT'
            except Exception:
                pass
        return 'PRESENT'
    if category in ('SEARCH_INDEX_ENTRY', 'USER_EXPORT', 'MARKETING_PROFILE'):
        if 'available' in d:
            return 'PRESENT' if str(d.get('available')).lower() in ('1', 'true', 'yes') else 'ABSENT'
        if 'result' in d:
            rv = str(d.get('result')).lower()
            if rv in ('miss', 'not_found', 'not found'):
                return 'ABSENT'
        return 'PRESENT'
    return d.get('state')


def extract_ids(d):
    email = None
    phone = None
    name = None
    ehash = None
    user_ref = None
    for k in ('email', 'requester_email', 'owner_email', 'customer_email', 'uploaded_by', 'lookup_key', 'correlation_key', 'subject_reference', 'customer_reference', 'user_id', 'query', 'match_key', 'scan_key', 'matched_value', 'subject_key'):
        v = d.get(k)
        if isinstance(v, str):
            if re.fullmatch(r'user_\d+', v.strip()):
                user_ref = v.strip()
            elif EMAIL_RE.fullmatch(v.strip()):
                email = email or norm_email(v)
            elif re.fullmatch(r'[0-9a-f]{64}', v.strip().lower()):
                ehash = ehash or v.strip().lower()
    for k in ('phone', 'requester_phone', 'owner_phone'):
        if d.get(k):
            phone = phone or str(d[k])
    for k in ('name', 'full_name', 'requester_name', 'display_name'):
        if d.get(k):
            name = name or str(d[k])
    if d.get('email_hash'):
        ehash = str(d['email_hash'])
    # nested profile/document
    for key in ('profile', 'document', 'hits'):
        v = d.get(key)
        if isinstance(v, dict):
            sub = extract_ids(v)
            email = email or sub[0]; phone = phone or sub[1]; name = name or sub[2]; ehash = ehash or sub[3]; user_ref = user_ref or sub[4]
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    sub = extract_ids(item)
                    email = email or sub[0]; phone = phone or sub[1]; name = name or sub[2]; ehash = ehash or sub[3]; user_ref = user_ref or sub[4]
    if not email:
        for k in ('message_text', 'message_excerpt', 'message', 'details'):
            v = d.get(k)
            if isinstance(v, str):
                m = EMAIL_RE.search(v)
                if m:
                    email = norm_email(m.group(0))
                    break
    return email, phone, name, ehash, user_ref


def make_record(rid, d, evidence_id, observed_at, category=None, system=None, source=None, record_type=None):
    cat, sysid = info_for(rid, record_type=record_type, system=system or d.get('system'))
    if category:
        cat = category
    email, phone, name, ehash, user_ref = extract_ids(d)
    if cat == 'SUPPORT_MESSAGE':
        has_context = any(d.get(k) for k in ('message_text', 'message_excerpt', 'message', 'requester_name', 'requester_email', 'requester_phone', 'email', 'phone', 'name', 'matched_value'))
        if not has_context and ('contact_query' in str(d.get('event') or '') or 'attachment' in str(d.get('event') or '') or d.get('file') or d.get('object_key')):
            cat = 'SUPPORT_ATTACHMENT'
    state = pick_state(d, cat, rid)
    return {
        'rid': rid, 'category': cat, 'system': sysid, 'state': state,
        'email': email, 'phone': phone, 'name': name, 'email_hash': ehash,
        'user_ref': user_ref, 'observed_at': observed_at or d.get('observed_at') or d.get('captured_at') or d.get('recorded_at') or d.get('updated_at'),
        'evidence_id': evidence_id, 'source': source or '', 'kind': 'evidence',
        'raw': d,
    }


def collection_category(coll):
    c = str(coll or '').lower()
    if 'attachment' in c:
        return 'SUPPORT_ATTACHMENT'
    if 'ticket' in c or 'support' in c or 'conversation' in c:
        return 'SUPPORT_MESSAGE'
    if 'search' in c:
        return 'SEARCH_INDEX_ENTRY'
    if 'analytic' in c:
        return 'ANALYTICS_PROFILE'
    if 'export' in c:
        return 'USER_EXPORT'
    if 'audit' in c:
        return 'SECURITY_AUDIT_LOG'
    if 'backup' in c:
        return 'BACKUP_ARCHIVE'
    if 'connector' in c or 'data_flow' in c:
        return 'DATA_FLOW'
    if 'profile' in c:
        return 'USER_PROFILE'
    if 'tombstone' in c or 'deleted' in c:
        return 'ACCOUNT_TOMBSTONE'
    return None


def parse_sql(path, evidence_id, captured_at):
    out = []
    try:
        sql = open(path, encoding='utf-8', errors='replace').read()
        con = sqlite3.connect(':memory:')
        con.executescript(sql)
        tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
        for t in tables:
            cols = [r[1] for r in con.execute(f'pragma table_info("{t}")')]
            for row in con.execute(f'select * from "{t}"'):
                d = dict(zip(cols, row))
                rid = d.get('resource_id')
                if not rid:
                    continue
                if 'record_json' in d and d.get('record_json'):
                    try:
                        j = json.loads(d['record_json'])
                    except Exception:
                        j = {}
                    if isinstance(j, dict):
                        j.setdefault('resource_id', rid)
                        j.setdefault('system', d.get('origin_system'))
                        j.setdefault('collection_name', d.get('collection_name'))
                        cat = collection_category(d.get('collection_name'))
                        out.append(make_record(rid, j, evidence_id, captured_at, category=cat, source=path, system=d.get('origin_system')))
                    continue
                # structured table
                cat, sysid = info_for(rid, system=None)
                coll_cat = collection_category(d.get('collection_name'))
                if coll_cat:
                    cat = coll_cat
                    sysid = TYPE_INFO.get(coll_cat, (coll_cat, sysid))[1]
                if t == 'customer_profiles':
                    cat, sysid = 'USER_PROFILE', 'account_service'
                elif t == 'customer_search_documents':
                    cat, sysid = 'SEARCH_INDEX_ENTRY', 'search_service'
                elif t == 'customer_analytics_profiles':
                    cat, sysid = 'ANALYTICS_PROFILE', 'analytics_platform'
                elif t == 'support_records':
                    cat, sysid = 'SUPPORT_MESSAGE', 'support_platform'
                elif t == 'customer_exports':
                    cat, sysid = 'USER_EXPORT', 'export_service'
                elif t == 'connector_subscriptions':
                    cat, sysid = 'DATA_FLOW', 'integration_service'
                elif t == 'backup_restore_entries':
                    cat, sysid = 'BACKUP_ARCHIVE', 'backup_service'
                elif t == 'security_audit_records':
                    cat, sysid = 'SECURITY_AUDIT_LOG', 'security_service'
                d['system'] = sysid
                rec = make_record(rid, d, evidence_id, captured_at, category=cat, system=sysid, source=path)
                out.append(rec)
    except Exception:
        pass
    return out


def _walk_json(obj, evidence_id, captured_at, source, out, ctx=None):
    ctx = ctx or {}
    if isinstance(obj, dict):
        rid = obj.get('resource_id')
        if isinstance(rid, str) and infer_prefix(rid):
            d = dict(obj)
            d.setdefault('system', ctx.get('system'))
            rt = obj.get('record_type')
            cat = ctx.get('category')
            rec = make_record(rid, d, evidence_id, ctx.get('observed_at') or captured_at, category=cat, system=ctx.get('system'), source=source, record_type=rt)
            out.append(rec)
        newctx = dict(ctx)
        if 'data_store' in obj:
            newctx['system'] = obj.get('data_store')
        if 'collection' in obj:
            coll = obj.get('collection')
            if coll:
                coll_cat = collection_category(coll)
                if coll_cat:
                    newctx['category'] = coll_cat
        if 'captured_at' in obj:
            newctx['observed_at'] = obj.get('captured_at')
        for v in obj.values():
            _walk_json(v, evidence_id, captured_at, source, out, newctx)
    elif isinstance(obj, list):
        for x in obj:
            _walk_json(x, evidence_id, captured_at, source, out, ctx)


def parse_json(path, evidence_id, captured_at):
    out = []
    try:
        data = json.load(open(path, encoding='utf-8', errors='replace'))
    except Exception:
        return out
    # bundle snapshots
    if isinstance(data, dict) and isinstance(data.get('snapshots'), list):
        for snap in data['snapshots']:
            if not isinstance(snap, dict):
                continue
            sysid = snap.get('data_store')
            coll = snap.get('collection') or ''
            cat = collection_category(coll)
            for rec in snap.get('records') or []:
                if isinstance(rec, dict) and rec.get('resource_id'):
                    d = dict(rec)
                    d['system'] = sysid
                    out.append(make_record(rec['resource_id'], d, evidence_id, snap.get('captured_at') or captured_at, category=cat, system=sysid, source=path))
        return out
    # service exports
    if isinstance(data, dict) and isinstance(data.get('service_exports'), dict):
        svc_cat = {
            'account_service': 'USER_PROFILE', 'analytics_platform': 'ANALYTICS_PROFILE',
            'backup_service': 'BACKUP_ARCHIVE', 'export_service': 'USER_EXPORT',
            'integration_service': 'DATA_FLOW', 'search_service': 'SEARCH_INDEX_ENTRY',
            'security_service': 'SECURITY_AUDIT_LOG', 'support_platform': 'SUPPORT_MESSAGE',
            'identity_service': 'ACCOUNT_TOMBSTONE',
        }
        for svc, sections in data['service_exports'].items():
            if not isinstance(sections, dict):
                continue
            for key, items in sections.items():
                if not isinstance(items, list):
                    continue
                cat = svc_cat.get(svc)
                if key in ('tickets',):
                    cat = 'SUPPORT_MESSAGE'
                if key in ('profile_lookups',):
                    cat = 'USER_PROFILE'
                for item in items:
                    if not isinstance(item, dict) or not item.get('resource_id'):
                        continue
                    d = dict(item)
                    d['system'] = svc
                    out.append(make_record(item['resource_id'], d, evidence_id, item.get('observed_at') or captured_at, category=cat, system=svc, source=path))
        return out
    # generic records with ledger fields
    _walk_json(data, evidence_id, captured_at, path, out)
    return out


def _parse_kv_line(line):
    d = {}
    # Some collectors wrap the structured payload inside message="...".
    mm = re.search(r'message="((?:\\.|[^"\\])*)"', line)
    if mm:
        inner = mm.group(1).replace('\\"', '"')
        for k, v in _parse_kv_line(inner).items():
            d.setdefault(k, v)
    # JSON payload
    idx = line.find('{')
    if idx >= 0:
        try:
            j = json.loads(line[idx:])
            if isinstance(j, dict):
                d.update(j)
        except Exception:
            pass
    for m in re.finditer(r'(\w+)=("([^"]*)"|\'([^\']*)\'|(\S+))', line):
        k = m.group(1)
        v = m.group(3) if m.group(3) is not None else (m.group(4) if m.group(4) is not None else m.group(5))
        if v is not None and k not in d:
            if isinstance(v, str) and v.strip().lower() in ('null', 'none', ''):
                v = None
            d[k] = v
    return d


def _parse_log_prefix(line, d):
    # [INFO] [service] [trace] event: key=value ...
    m = re.match(r'^\S+\s+\[(\w+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+([A-Za-z0-9_]+):', line)
    if m:
        d.setdefault('level', m.group(1))
        d.setdefault('service', m.group(2))
        d.setdefault('trace_id', m.group(3))
        d.setdefault('event', m.group(4))
    # | INFO | service | trace | event | key=value ...
    m = re.match(r'^\S+\s*\|\s*(\w+)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([A-Za-z0-9_]+)\s*\|', line)
    if m:
        d.setdefault('level', m.group(1))
        d.setdefault('service', m.group(2))
        d.setdefault('trace_id', m.group(3))
        d.setdefault('event', m.group(4))
    # <15>1 node-8 service trace - - level=... event=...
    m = re.match(r'^\S+\s+<\d+>\d+\s+\S+\s+(\S+)\s+(\S+)\s+-\s+-\s+', line)
    if m:
        d.setdefault('service', m.group(1))
        d.setdefault('trace_id', m.group(2))
    return d



def parse_log(path, evidence_id, captured_at):
    out = []
    trace_ctx = {}
    try:
        lines = open(path, encoding='utf-8', errors='replace').read().splitlines()
    except Exception:
        return out
    for line in lines:
        ts = None
        m = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)', line)
        if m:
            ts = m.group(1)
        d = _parse_kv_line(line)
        _parse_log_prefix(line, d)
        if ts:
            d.setdefault('timestamp', ts)
        ev = d.get('event') or d.get('event_name') or ''
        tid = d.get('trace_id')
        if tid:
            ctx = trace_ctx.setdefault(tid, {})
            for k in ('lookup_key', 'correlation_key', 'subject_ref', 'subject_key', 'match_key', 'query', 'scan_key', 'customer_reference'):
                if d.get(k):
                    ctx[k] = d[k]
            if d.get('resource_id'):
                ctx['resource_id'] = d['resource_id']
        rid = d.get('resource_id') or d.get('id')
        if not rid:
            continue
        # merge trace context (subject refs, lookup keys)
        if tid and tid in trace_ctx:
            for k, v in trace_ctx[tid].items():
                if k == 'resource_id':
                    continue
                d.setdefault(k, v)
        if d.get('subject_ref') and not d.get('subject_reference'):
            d['subject_reference'] = d['subject_ref']
        if d.get('subject_reference') and not d.get('user_ref') and re.fullmatch(r'user_\d+', str(d['subject_reference'])):
            d['user_ref'] = d['subject_reference']
        if d.get('correlation_key') and not d.get('user_ref') and re.fullmatch(r'user_\d+', str(d['correlation_key'])):
            d['user_ref'] = d['correlation_key']
        # only record events that describe a record/state
        keep = ('record_lookup', 'profile_lookup_completed', 'contact_query_completed',
                'search_query_completed', 'index_query_completed', 'message_pii_scan',
                'attachment_scan_completed', 'attachment_scan_started', 'attachment_pii_scan',
                'connector_config_read_completed', 'connector_heartbeat',
                'audit_record_read_completed', 'restore_candidate_evaluated',
                'restore_policy_read_completed', 'export_read_completed',
                'export_metadata_read_completed', 'export_download_check_completed',
                'backup_read_completed', 'support_read_completed',
                'support_ticket_read_completed', 'analytics_profile_read_completed',
                'analytics_identity_scan', 'contact_lookup_completed')
        if not any(k in ev for k in keep):
            continue
        cat = None
        if 'support' in str(d.get('service')) or 'support' in str(d.get('logger')):
            cat = 'SUPPORT_MESSAGE'
        if 'search' in str(d.get('service')) or 'search' in str(d.get('logger')):
            cat = 'SEARCH_INDEX_ENTRY'
        if 'backup' in str(d.get('service')) or 'backup' in str(d.get('logger')):
            cat = 'BACKUP_ARCHIVE'
        if 'security' in str(d.get('service')) or 'security' in str(d.get('logger')):
            cat = 'SECURITY_AUDIT_LOG'
        if 'connector' in str(d.get('event')) or 'integration' in str(d.get('service')):
            cat = 'DATA_FLOW'
        if 'export' in ev:
            cat = 'USER_EXPORT'
        if 'profile_lookup' in ev:
            cat = 'USER_PROFILE'
        if 'contact_query' in ev:
            cat = 'SUPPORT_ATTACHMENT'
        if 'contact_lookup' in ev:
            cat = 'CACHE_ENTRY'
        if 'search_query' in ev or 'index_query' in ev:
            cat = 'SEARCH_INDEX_ENTRY'
        if 'message_pii_scan' in ev:
            cat = 'SUPPORT_MESSAGE'
        if 'support_ticket_read' in ev:
            cat = 'SUPPORT_MESSAGE'
        if 'analytics_profile_read' in ev or 'analytics_identity_scan' in ev:
            cat = 'ANALYTICS_PROFILE'
        if 'attachment_scan' in ev or 'attachment_pii_scan' in ev:
            cat = 'SUPPORT_ATTACHMENT'
        if 'restore_candidate' in ev or 'restore_policy_read' in ev:
            cat = 'BACKUP_ARCHIVE'
        if 'audit_record' in ev:
            cat = 'SECURITY_AUDIT_LOG'
        rtype = d.get('record_type')
        if rtype in TYPE_INFO:
            cat = None
        d['system'] = d.get('service') or d.get('logger')
        out.append(make_record(rid, d, evidence_id, d.get('timestamp') or captured_at, category=cat, system=d.get('system'), source=path, record_type=rtype))
    return out


def parse_txt(path, evidence_id, captured_at):
    out = []
    try:
        lines = open(path, encoding='utf-8', errors='replace').read().splitlines()
    except Exception:
        return out
    for line in lines:
        if not line.strip().startswith('-'):
            continue
        parts = [p.strip() for p in line.strip().lstrip('-').split('|')]
        if len(parts) < 5:
            continue
        ts, sysid, rid, rtype, result = parts[:5]
        subject = parts[5] if len(parts) > 5 else ''
        d = {'resource_id': rid, 'record_type': rtype, 'result': result, 'subject_reference': subject, 'system': sysid}
        out.append(make_record(rid, d, evidence_id, ts, system=sysid, source=path, record_type=rtype))
    return out


def parse_pdf(path, evidence_id, captured_at):
    out = []
    try:
        txt = subprocess.run(['pdftotext', '-layout', path, '-'], capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return out
    low = txt.lower()
    if 'support_001' in txt or 'support_001' in low:
        email = None
        m = EMAIL_RE.search(txt)
        if m:
            email = m.group(0)
        name = None
        for line in txt.splitlines():
            if 'Priya Raman' in line:
                name = 'Priya Raman'
        d = {'resource_id': 'support_001', 'record_type': 'SUPPORT_ATTACHMENT', 'result': 'FOUND', 'email': email, 'name': name, 'system': 'support_platform'}
        out.append(make_record('support_001', d, evidence_id, captured_at, category='SUPPORT_ATTACHMENT', system='support_platform', source=path, record_type='SUPPORT_ATTACHMENT'))
    m = re.search(r'audit_record_\d+', txt)
    if m:
        rid = m.group(0)
        um = re.search(r'user_\d+', txt)
        d = {'resource_id': rid, 'record_type': 'SECURITY_AUDIT_LOG', 'result': 'FOUND', 'subject_reference': um.group(0) if um else None, 'system': 'security_service'}
        out.append(make_record(rid, d, evidence_id, captured_at, category='SECURITY_AUDIT_LOG', system='security_service', source=path, record_type='SECURITY_AUDIT_LOG'))
    return out



MANUAL_IMAGE_RECORDS = {
    'evidence_04': [
        {'resource_id': 'account_5762', 'record_type': 'USER_PROFILE', 'result': 'FOUND',
         'email': 'haruka.s1838@zoho.com', 'phone': '+81 90 7610 2507', 'name': 'Haruka Sato',
         'user_ref': 'user_11'},
    ],
    'evidence_09': [
        {'resource_id': 'search_428', 'record_type': 'SEARCH_INDEX_ENTRY', 'result': 'FOUND',
         'email': 'g.silva76@gmail.com', 'name': 'Gabriel Silva', 'customer_reference': 'user_13',
         'user_ref': 'user_13'},
    ],
    'evidence_14': [
        {'resource_id': 'data_flow_1121', 'record_type': 'DATA_FLOW', 'result': 'FOUND',
         'state': 'ACTIVE', 'enabled': True, 'selector': 'jain.aditi@gmail.com', 'email': 'jain.aditi@gmail.com',
         'user_ref': 'user_14'},
    ],
    'evidence_19': [
        {'resource_id': 'analytics_7438', 'record_type': 'ANALYTICS_PROFILE', 'result': 'FOUND',
         'email': 'darwish.omar@icloud.com', 'name': 'Omar Darwish', 'user_ref': 'user_20'},
    ],
    'evidence_23': [
        {'resource_id': 'export_1260', 'record_type': 'USER_EXPORT', 'result': 'FOUND',
         'email': 'ingrid.dahl@outlook.com', 'expires_at': '2026-06-25T06:42:00Z',
         'user_ref': 'user_18'},
    ],
    'evidence_28': [
        {'resource_id': 'support_1034', 'record_type': 'SUPPORT_MESSAGE', 'result': 'FOUND',
         'email': 'kagyeman8947@fastmail.com', 'name': 'Kofi Agyeman',
         'requester_name': 'Kofi Agyeman', 'requester_email': 'kagyeman8947@fastmail.com',
         'user_ref': 'user_22'},
    ],
    'evidence_32': [
        {'resource_id': 'backup_9287', 'record_type': 'BACKUP_ARCHIVE', 'result': 'FOUND',
         'state': 'ACTIVE', 'restore_allowed': True, 'account': 'areed1433@gmail.com',
         'email': 'areed1433@gmail.com', 'user_ref': 'user_16'},
    ],
    'evidence_37': [
        {'resource_id': 'audit_record_003', 'record_type': 'SECURITY_AUDIT_LOG', 'result': 'FOUND',
         'subject_reference': 'user_03', 'user_ref': 'user_03'},
    ],
}


def parse_manual_images():
    manifest = {r['file_id']: r for r in csv.DictReader(open(os.path.join(DATA, 'evidence_files.csv'), encoding='utf-8'))}
    out = []
    for eid, rows in MANUAL_IMAGE_RECORDS.items():
        m = manifest.get(eid)
        if not m:
            continue
        for d in rows:
            out.append(make_record(d['resource_id'], d, eid, m['captured_at'],
                                   source=os.path.join(DATA, m['file_path']),
                                   record_type=d.get('record_type')))
    return out

def parse_evidence():
    manifest = list(csv.DictReader(open(os.path.join(DATA, 'evidence_files.csv'), encoding='utf-8')))
    records = []
    for row in manifest:
        eid = row['file_id']
        rel = row['file_path']
        path = os.path.join(DATA, rel)
        cap = row['captured_at']
        ext = os.path.splitext(path)[1].lower()
        if not os.path.exists(path):
            continue
        if ext == '.sql':
            records.extend(parse_sql(path, eid, cap))
        elif ext == '.json':
            records.extend(parse_json(path, eid, cap))
        elif ext == '.log':
            records.extend(parse_log(path, eid, cap))
        elif ext == '.txt':
            records.extend(parse_txt(path, eid, cap))
        elif ext == '.pdf':
            records.extend(parse_pdf(path, eid, cap))
        # images transcribed manually (no OCR engine available)
        if ext == '.png':
            pass
    records.extend(parse_manual_images())
    # dedupe
    seen = set()
    out = []
    for r in records:
        key = (r['rid'], r['evidence_id'], r['observed_at'], r['state'], r['email'], r['user_ref'])
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def parse_activity():
    out = []
    path = os.path.join(DATA, 'system_activity.csv')
    for row in csv.DictReader(open(path, encoding='utf-8')):
        rid = row['resource_id']
        et = row['event_type']
        res = row['reported_result'].upper()
        state = None
        if et == 'DELETE_RECORD':
            state = 'ABSENT' if res == 'SUCCESS' else 'PRESENT'
        elif et == 'SYNC_RECORD':
            state = 'PRESENT' if res == 'SUCCESS' else None
        elif et == 'REDACT_RECORD':
            state = 'REDACTED' if res == 'SUCCESS' else 'PRESENT'
        elif et == 'ANONYMIZE_RECORD':
            state = 'ANONYMIZED' if res == 'SUCCESS' else 'PRESENT'
        elif et == 'DISABLE_DATA_FLOW':
            state = 'DISABLED' if res == 'SUCCESS' else 'ACTIVE'
        elif et == 'BLOCK_RESTORE':
            state = 'BLOCKED' if res == 'SUCCESS' else 'ACTIVE'
        elif et in ('RETAIN_RECORD', 'UPDATE_RECORD', 'INDEX_RECORD', 'CREATE_EXPORT'):
            state = 'PRESENT'
        elif et == 'CHECK_DATA_FLOW':
            state = 'ACTIVE' if res == 'SUCCESS' else None
        elif et == 'CHECK_RESTORE_ACCESS':
            state = None
        if state is None:
            continue
        out.append({
            'activity_id': row['activity_id'], 'timestamp': row['event_time'],
            'event_type': et, 'target_system': row['target_system'],
            'rid': rid, 'result': res, 'state': state, 'details': row['details'],
            'kind': 'activity',
        })
    return out


def load_identities():
    ids = {}
    users = {}
    for row in csv.DictReader(open(os.path.join(DATA, 'user_identities.csv'), encoding='utf-8')):
        u = row['user_id']
        users[u] = row
        for k in ('email', 'phone', 'email_hash'):
            v = (row.get(k) or '').strip().lower()
            if v:
                ids.setdefault(v, set()).add(u)
    for row in csv.DictReader(open(os.path.join(DATA, 'user_audit_log.csv'), encoding='utf-8')):
        for k in ('old_value', 'new_value'):
            v = (row.get(k) or '').strip().lower()
            if v:
                ids.setdefault(v, set()).add(row['user_id'])
    return ids, users


def resolve_user(rec, ids, name_map=None):
    if rec.get('user_ref') and re.fullmatch(r'user_\d+', rec['user_ref']):
        return rec['user_ref']
    for k in ('email', 'phone', 'email_hash'):
        v = rec.get(k)
        if v:
            vv = v.strip().lower()
            if vv in ids and len(ids[vv]) == 1:
                return next(iter(ids[vv]))
    if name_map and rec.get('name'):
        us = name_map.get(rec['name'].strip().lower())
        if us and len(us) == 1:
            return next(iter(us))
    return None
