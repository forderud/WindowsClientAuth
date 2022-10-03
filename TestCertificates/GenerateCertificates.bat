:: Based on https://stackoverflow.com/questions/11031200/how-do-i-create-client-certificates-for-local-testing-of-two-way-authentication
:: Must be run from a developer program prompt

:: Add OpenSSL to PATH
set "PATH=%PATH%;C:\Program Files\Git\usr\bin"

:: Generate root certificate
makecert.exe -r -n "CN=TestRootCertificate" -pe -sv TestRootCertificate.pvk -a sha256 -len 2048 -m 120 -cy authority TestRootCertificate.cer
:: Bundle to .pfx
pvk2pfx.exe -pvk TestRootCertificate.pvk -spc TestRootCertificate.cer -pfx TestRootCertificate.pfx
:: Convert to PEM for OpenSSL compatibility
openssl.exe pkcs12 -in TestRootCertificate.pfx -out TestRootCertificate.pem -nodes


:: Generate client certificate from root certificate
:: The enhanced key usage (EKU) OID for clientAuth is 1.3.6.1.5.5.7.3.2
:: The enhanced key usage (EKU) OID for codeSigning is 1.3.6.1.5.5.7.3.3
:: The enhanced key usage (EKU) OID for Encrypting File System is 1.3.6.1.4.1.311.10.3.4
makecert.exe -ic TestRootCertificate.cer -iv TestRootCertificate.pvk -sv ClientCert.pvk -a sha256 -n "CN=ClientCert" -len 2048 -m 120 ClientCert.cer -eku 1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.10.3.4
:: Bundle to .pfx
pvk2pfx.exe -pvk ClientCert.pvk -spc ClientCert.cer -pfx ClientCert.pfx
:: Convert to PEM for OpenSSL compatibility
openssl.exe pkcs12 -in ClientCert.pfx -out ClientCert.pem -nodes


:: Generate web server certificate from root certificate
:: Use OpenSSL instead of makecert since we need the "subjectAltName" extension to avoid "Not secure" warnings in web browsers
::
:: Create certificate signing request (CSR)
:: Doc: https://www.openssl.org/docs/manmaster/man1/openssl-req.html
openssl.exe req -newkey rsa:2048 -subj "/CN=localhost" -keyout localhost.key -out localhost.csr -nodes
:: Sign certificate with root certificate
:: Doc: https://www.openssl.org/docs/manmaster/man1/openssl-x509.html
openssl.exe x509 -req -extfile localhost.ini -extensions MyCustomExtensions -CA TestRootCertificate.pem -CAcreateserial -in localhost.csr -out localhost.crt -days 3650
