import os, http.server, ssl, sys

hostname = ("", 443) # default
if len(sys.argv) > 1:
    host_port = sys.argv[1].split(":")
    hostname = (host_port[0], int(host_port[1]))

# Server certificate. The client needs to trust the issuer (CA) of this certificate.
KEY_FILE = os.path.join(os.path.dirname(__file__), 'TestCertificates\\localhost.key') # path relative to this script

def ParseCertSequence(cert):
    entries = []
    for entry in cert:
        elm = entry[0]
        entries.append("("+elm[0]+': '+elm[1]+")")
    return '; '.join(entries)

class MyServer(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # get client cert info
        cert = self.connection.getpeercert()
        client_cert = "None"
        client_cert_issuer = "None"
        if cert:
            client_cert = ParseCertSequence(cert['subject'])
            client_cert_issuer = ParseCertSequence(cert['issuer'])
        
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(bytes("<html><head><title>Client certificate authentication test</title></head>\n", "utf-8"))
        self.wfile.write(bytes("<body>\n", "utf-8"))
        self.wfile.write(bytes("<p>Request path: %s</p>\n" % self.path, "utf-8"))
        self.wfile.write(bytes("<p>Successfully validated <b>client certificate</b>: {}, issued by {}.</p>\n".format(client_cert, client_cert_issuer), "utf-8"))
        self.wfile.write(bytes("</body></html>\n", "utf-8"))

with http.server.HTTPServer(hostname, MyServer) as httpd:
    print("serving at " + str(hostname))
    
    # DOC: https://docs.python.org/3/library/ssl.html
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.verify_mode = ssl.CERT_OPTIONAL # or ssl.CERT_REQUIRED
    context.load_default_certs(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(KEY_FILE) # server identity
    httpd.socket = context.wrap_socket(sock=httpd.socket, server_side=True)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    httpd.server_close()
    print("Server stopped.")
