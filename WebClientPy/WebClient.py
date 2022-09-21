import os, http.client, ssl, sys

hostname = ("localhost", 443) # default
if len(sys.argv) > 1:
    host_port = sys.argv[1].split(":")
    hostname = (host_port[0], int(host_port[1]))

# file paths relative to this script
# TODO: Load certificate from Windows certificate store instead of file (see https://stackoverflow.com/questions/55229786/loading-certificates-into-ssl-with-certs-store-not-file-path-with-python)
CERT_FILE = os.path.join(os.path.dirname(__file__), '..\\TestCertificates\\ClientCert.pem')

# configure client certificate
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_default_certs()
context.load_cert_chain(certfile=CERT_FILE)

# submit HTTP request
conn = http.client.HTTPSConnection(hostname[0], port=hostname[1], context=context)
conn.request('GET', '/')

# print response
r = conn.getresponse()
print(r.read())
