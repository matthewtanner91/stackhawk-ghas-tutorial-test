"""Run the real scanner; publish only validated synthetic SARIF and safe counters."""
import json, os, pathlib, re, subprocess, sys, tempfile, time, urllib.request
root=pathlib.Path.cwd()
def abort(message):
    print(message, file=sys.stderr); raise SystemExit(1)
def capture(args):
    r=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=600)
    return r
server=subprocess.Popen([sys.executable,'server.py'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
try:
    for attempt in range(50):
        try:
            with urllib.request.urlopen('http://127.0.0.1:8768/search?q=hello',timeout=1) as response:
                assert response.status==200
            break
        except Exception: time.sleep(.1)
    else: abort('Synthetic target did not start')
    version=capture(['hawk','version'])
    if '6.6.0' not in version.stdout: abort('Unexpected scanner version')
    os.environ['API_KEY']=os.environ['HAWK_API_KEY']
    scan=capture(['hawk','scan','--json-output','--sarif-ghas','stackhawk.yml'])
    if scan.returncode not in (0,42):
        combined=(scan.stdout+' '+scan.stderr).lower()
        hints=[word for word in ['unauthorized','authentication','api key','invalid','unknown option','no such option','not found','permission denied','connection refused','error'] if word in combined]
        print('Safe failure categories: '+json.dumps(hints)+'; exit='+str(scan.returncode))
        abort('Scanner did not complete; raw logs withheld')
    try: result=json.loads(scan.stdout)
    except Exception: abort('Scanner returned no structured result; raw logs withheld')
    sid=result.get('scan',{}).get('id','')
    if not re.fullmatch(r'[a-f0-9-]{36}',sid): abort('Missing valid scan identity')
    if result.get('scan',{}).get('status')!='COMPLETED' or result.get('errors'): abort('Scan health failed')
    metrics=capture(['hawk','op','scan','metrics',sid,'--format','json','--top','1000'])
    if metrics.returncode: abort('Could not verify scan health metrics')
    try: health=json.loads(metrics.stdout)
    except Exception: abort('Could not parse scan health metrics')
    sarif=root/'stackhawk-ghas.sarif'
    if not sarif.exists(): abort('Expected genuine GHAS SARIF export absent')
    raw=sarif.read_text()
    # Reject any credential or private app metadata before publication.
    forbidden=[os.environ.get(k,'') for k in ['HAWK_API_KEY','TEST_APP_ID','TEST_POLICY']]
    if any(value and value in raw for value in forbidden) or re.search(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',raw): abort('Export contains private metadata; publication stopped')
    data=json.loads(raw)
    if data.get('version')!='2.1.0': abort('Unexpected SARIF version')
    results=[x for run in data.get('runs',[]) for x in run.get('results',[])]
    if not results: abort('No genuine findings to verify in GitHub')
    # Whitelist external links: only vendor vulnerability/documentation pages.
    urls=re.findall(r'https?://[^\s"<>]+',raw)
    for url in urls:
        if not url.startswith(('https://docs.stackhawk.com/','https://vuln.stackhawk.com/','https://schemastore.azurewebsites.net/','https://json.schemastore.org/','http://127.0.0.1:8768','https://stackhawk.com','https://www.stackhawk.com','https://app.stackhawk.com/scans/'+sid)):
            abort('Export has an unexpected external link; publication stopped')
    summary={'scan_id':sid,'status':'COMPLETED','scanner':'6.6.0','sarif_results':len(results),'rule_ids':sorted({str(x.get('ruleId')) for x in results}),'scan_errors':len(result.get('errors',[])),'scan_warnings':len(result.get('warnings',[]))}
    print(json.dumps(summary,sort_keys=True))
    # Safe aggregate metrics only; never include app, user, policy, request or header data.
    def counters(obj):
        out={}
        if isinstance(obj,dict):
            for k,v in obj.items():
                if isinstance(v,(int,float)) and any(term in k.lower() for term in ['timeout','connection','request','error']):out[k]=v
                elif isinstance(v,dict):out.update(counters(v))
        return out
    safe=counters(health);print('Health counters: '+json.dumps(safe,sort_keys=True))
    if any(v for k,v in safe.items() if 'timeout' in k.lower() or 'connectionfailure' in k.lower().replace('_','')):abort('Scan health counters require inspection before upload')
finally:
    server.terminate()
    try:server.wait(timeout=5)
    except subprocess.TimeoutExpired:server.kill();server.wait()
