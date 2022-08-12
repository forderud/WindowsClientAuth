import os, http.client, ssl

# file paths relative to this script
CERT_FILE = os.path.join(os.path.dirname(__file__), 'TestCertificates\\ClientCert.pem')

# configure client certificate
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_default_certs()
context.load_cert_chain(certfile=CERT_FILE)

# submit HTTP request
conn = http.client.HTTPSConnection('localhost', port=4443, context=context)
conn.request('GET', '/')

# print response
r = conn.getresponse()
print(r.read())
