#!/usr/bin/env python

"""A simple HTTP server with REST and json for python 3.
addrecord takes utf8-encoded URL parameters
getrecord returns utf8-encoded json.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import argparse
import re
import cgi
import json
import threading
from urllib import parse


class LocalData(object):
    records = {}


class HTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if re.search('/api/v1/addrecord/*', self.path):
            ctype, pdict = cgi.parse_header(
                self.headers.get('content-type'))
            if ctype == 'application/json':
                length = int(self.headers.get('content-length'))
                rfile_str = self.rfile.read(length).decode('utf8')
                data = parse.parse_qs(rfile_str, keep_blank_values=1)
                record_id = self.path.split('/')[-1]
                LocalData.records[record_id] = data
                print("addrecord %s: %s" % (record_id, data))
                # HTTP 200: ok
                self.send_response(200)
            else:
                # HTTP 400: bad request
                self.send_response(400, "Bad Request: must give data")
        else:
            # HTTP 403: forbidden
            self.send_response(403)

        self.end_headers()

    def do_GET(self):
        if re.search('/api/v1/shutdown', self.path):
            # Must shutdown in another thread or we'll hang
            def kill_me_please():
                self.server.shutdown()
            threading.Thread(target=kill_me_please).start()

            # Send out a 200 before we go
            self.send_response(200)
        elif re.search('/api/v1/getrecord/*', self.path):
            record_id = self.path.split('/')[-1]
            if record_id in LocalData.records:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                # Return json, even though it came in as POST URL params
                data = json.dumps(LocalData.records[record_id])
                print("getrecord %s: %s" % (record_id, data))
                self.wfile.write(data.encode('utf8'))
            else:
                self.send_response(404, 'Not Found: record does not exist')
        else:
            self.send_response(403)

        self.end_headers()

def main():
    #parser = argparse.ArgumentParser(description='HTTP Server')
    #parser.add_argument('port', type=int, help='Listening port for HTTP Server')
    #parser.add_argument('ip', help='HTTP Server IP')
    #args = parser.parse_args()
    ip = '127.0.0.1'
    port = 9999
    server = HTTPServer((ip, port), HTTPRequestHandler)
    print('HTTP Server Running...........')
    server.serve_forever()


""" Usage:

Copy paste the code above and name it simplewebserver.py
Starting WebServer:
python simplewebserver.py
POST addrecord example using curl:
curl -X POST http://localhost:9999/api/v1/addrecord/1 -d '{\"Bilz\":\"test\"}' -H "Content-Type: application/json"
GET record example using curl:
curl -X GET http://localhost:9999/api/v1/getrecord/1 -H "Content-Type: application/json" 
"""

if __name__ == '__main__':
    main()

if __name__=='__main__':
  #parser = argparse.ArgumentParser(description='HTTP Server')
  #parser.add_argument('port', type=int, help='Listening port for HTTP Server')
  #parser.add_argument('ip', help='HTTP Server IP')
  #args = parser.parse_args()

  #server = SimpleHttpServer(args.ip, args.port)
  server = SimpleHttpServer('127.0.0.1', 9999)
  print('HTTP Server Running........... ')
  server.start()
  server.waitForThread()