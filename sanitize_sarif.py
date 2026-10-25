"""Remove only optional identifying metadata; reject secrets everywhere."""
import copy,json,re
from urllib.parse import urlsplit

def sanitize(data,credential,private_values):
    original=json.dumps(data,ensure_ascii=False)
    if credential and credential in original:
        raise ValueError('Credential detected; publication stopped')
    clean=copy.deepcopy(data)
    for run in clean.get('runs',[]):
        run.get('automationDetails',{}).pop('description',None)
    rendered=json.dumps(clean,ensure_ascii=False)
    if any(value and value in rendered for value in private_values):
        raise ValueError('Private metadata remains outside optional description; publication stopped')
    if re.search(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',rendered):
        raise ValueError('Email pattern remains; publication stopped')
    for before,after in zip(data.get('runs',[]),clean.get('runs',[])):
        if before.get('results')!=after.get('results') or before.get('tool')!=after.get('tool'):
            raise ValueError('Finding preservation check failed')
    return clean


HTTPS_HOSTS = frozenset({
    'docs.stackhawk.com', 'vuln.stackhawk.com', 'stackhawk.com',
    'www.stackhawk.com', 'schemastore.azurewebsites.net', 'json.schemastore.org',
})

def allowed_export_url(url, scan_id):
    """Match parsed origins, reject userinfo, and bind platform links to this scan."""
    if any(ord(c) <= 32 or ord(c) == 127 for c in url) or '\\' in url:
        return False
    try:
        parsed = urlsplit(url)
        host, port = parsed.hostname, parsed.port
        if parsed.username is not None or parsed.password is not None:
            return False
    except ValueError:
        return False
    if parsed.scheme == 'http':
        return host == '127.0.0.1' and port == 8768
    if parsed.scheme != 'https' or port not in (None, 443):
        return False
    if host == 'app.stackhawk.com':
        scan_path = '/scans/' + scan_id
        finding_path = re.fullmatch(re.escape(scan_path) + r'/finding/[0-9]+(?:-[0-9]+)?', parsed.path)
        return (parsed.path == scan_path or finding_path is not None) and not parsed.query and not parsed.fragment
    return host in HTTPS_HOSTS

def validate_export_urls(data, scan_id):
    """Inspect decoded SARIF strings without changing any finding content."""
    def visit(value):
        if isinstance(value, dict):
            for item in value.values(): visit(item)
        elif isinstance(value, list):
            for item in value: visit(item)
        elif isinstance(value, str):
            for url in re.findall(r'https?://[^\s"<>]+', value, flags=re.IGNORECASE):
                if not allowed_export_url(url.rstrip(')`'), scan_id):
                    raise ValueError('Export has an unexpected external link; publication stopped')
    visit(data)
