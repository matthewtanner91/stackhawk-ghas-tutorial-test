from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit,parse_qs
import json
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        u=urlsplit(self.path)
        if u.path=='/openapi.json':
            body=open('openapi.json','rb').read(); kind='application/json'
        elif u.path=='/search':
            q=parse_qs(u.query).get('q',['hello'])[0]
            body=('<!doctype html><html><body><h1>Synthetic search</h1><p>'+q+'</p></body></html>').encode();kind='text/html; charset=utf-8'
        else: self.send_error(404);return
        self.send_response(200);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*args): pass
if __name__=='__main__': ThreadingHTTPServer(('127.0.0.1',8768),Handler).serve_forever()
