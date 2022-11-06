# stop script on first error
$ErrorActionPreference = "Stop"

# PFX password (haven't figured out how to avoid it)
$pwd = ConvertTo-SecureString -String "1234" -AsPlainText -Force


# Generate root certificate
$root = New-SelfSignedCertificate -CertStoreLocation "Cert:\CurrentUser\My" -Type Custom -Subject "CN=TestRootCertificate" -KeyUsage None -TextExtension @("2.5.29.19={text}CA=true") -KeyExportPolicy Exportable -NotAfter(Get-Date).AddMonths(120)
Export-Certificate -Cert $root -FilePath "TestRootCertificate.cer"
Export-PfxCertificate -Cert $root -Password $pwd -FilePath "TestRootCertificate.pfx"
#$root = Import-PfxCertificate -CertStoreLocation "Cert:\CurrentUser\My" -Password $pwd -FilePath "TestRootCertificate.pfx"


# Generate client certificate from root certificate
# The enhanced key usage (EKU) OID for clientAuth is 1.3.6.1.5.5.7.3.2
# The enhanced key usage (EKU) OID for codeSigning is 1.3.6.1.5.5.7.3.3
$client = New-SelfSignedCertificate -CertStoreLocation "Cert:\CurrentUser\My" -Type Custom -Subject "CN=ClientCert" -KeyUsageProperty All -KeyUsage None -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.3") -KeyExportPolicy Exportable -KeyAlgorithm RSA -KeyLength 2048 -Signer $root -NotAfter(Get-Date).AddMonths(120)
Export-PfxCertificate -Cert $client -Password $pwd -FilePath "ClientCert.pfx"
#$client = Import-PfxCertificate -CertStoreLocation "Cert:\CurrentUser\My" -Password $pwd -FilePath "ClientCert.pfx"
# Convert to PEM for Python client compatibility
& "C:\Program Files\Git\usr\bin\openssl.exe" pkcs12 -in ClientCert.pfx -out ClientCert.pem -nodes -password pass:1234


# Generate web server certificate from root certificate
# The enhanced key usage (EKU) OID for serverAuth is 1.3.6.1.5.5.7.3.1
$localhost = New-SelfSignedCertificate -CertStoreLocation "Cert:\CurrentUser\My" -Type SSLServerAuthentication -DnsName "localhost" -KeyUsage None -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") -KeyExportPolicy Exportable -KeyAlgorithm RSA -KeyLength 2048 -Signer $root -NotAfter(Get-Date).AddMonths(120)
Export-PfxCertificate -Cert $localhost -Password $pwd -FilePath "localhost.pfx"
# Convert to PEM for Python server compatibility
& "C:\Program Files\Git\usr\bin\openssl.exe" pkcs12 -in localhost.pfx -out localhost.key -nodes -password pass:1234


# Generate expired certificate for test purposes
$expired = New-SelfSignedCertificate -CertStoreLocation "Cert:\CurrentUser\My" -Type Custom -Subject "CN=ExpiredCert" -KeyUsageProperty All -KeyUsage None -KeyExportPolicy Exportable -KeyAlgorithm RSA -KeyLength 2048 -NotBefore(Get-Date).AddMonths(-13) -NotAfter(Get-Date).AddMonths(-1)
Export-PfxCertificate -Cert $expired -Password $pwd -FilePath "ExpiredCert.pfx"
