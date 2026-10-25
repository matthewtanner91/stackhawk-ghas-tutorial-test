"""Remove only optional identifying metadata; reject secrets everywhere."""
import copy,json,re

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
