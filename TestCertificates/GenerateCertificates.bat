:: Based on https://stackoverflow.com/questions/11031200/how-do-i-create-client-certificates-for-local-testing-of-two-way-authentication

:: Generate root certificate
makecert.exe -r -n "CN=TestRootCertificate" -pe -sv TestRootCertificate.pvk -a sha256 -len 2048 -b 01/01/2022 -e 01/01/2023 -cy authority TestRootCertificate.cer
:: Bundle to .pfx
pvk2pfx.exe -pvk TestRootCertificate.pvk -spc TestRootCertificate.cer -pfx TestRootCertificate.pfx
:: Convert PFX to PEM for web-server consumption
"C:\Program Files\Git\usr\bin\openssl.exe" pkcs12 -in TestRootCertificate.pfx -out TestRootCertificate.pem -nodes


:: Generate client certificate from root certificate
makecert.exe -ic TestRootCertificate.cer -iv TestRootCertificate.pvk -pe -sv ClientCert.pvk -a sha256 -n "CN=ClientCert" -len 2048 -b 01/01/2022 -e 01/01/2023 -sky exchange ClientCert.cer -eku 1.3.6.1.5.5.7.3.2
:: Bundle to .pfx
pvk2pfx.exe -pvk ClientCert.pvk -spc ClientCert.cer -pfx ClientCert.pfx


:: Generate web server certificate from root certificate
:: Use OpenSSL instead of makecert to enable subjectAltName extension
::
:: Create certificate signing request (CSR)
:: Doc: https://www.openssl.org/docs/manmaster/man1/openssl-req.html
"C:\Program Files\Git\usr\bin\openssl.exe" req -newkey rsa:2048 -subj "/CN=localhost" -keyout localhost.key -out localhost.csr -nodes
:: Sign certificate with CA
:: Doc: https://www.openssl.org/docs/manmaster/man1/openssl-x509.html
"C:\Program Files\Git\usr\bin\openssl.exe" x509 -req -extfile openssl.ini -extensions MyCustomExtensions -CA TestRootCertificate.pem -CAcreateserial -in localhost.csr -out localhost.crt -days 365
