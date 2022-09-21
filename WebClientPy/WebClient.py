import os, http.client, ssl, sys

hostname = ("localhost", 443) # default
if len(sys.argv) > 1:
    host_port = sys.argv[1].split(":")
    hostname = (host_port[0], int(host_port[1]))

# configure client certificate
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_default_certs()
certs = context._load_windows_store_certs("My", ssl.Purpose.CLIENT_AUTH)
print(certs)

# submit HTTP request
conn = http.client.HTTPSConnection(hostname[0], port=hostname[1], context=context)
conn.request('GET', '/')

# print response
r = conn.getresponse()
print(r.read())
