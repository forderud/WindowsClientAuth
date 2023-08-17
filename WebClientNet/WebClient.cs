using Microsoft.Win32;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


bool IsClientAuthCertificate(X509Certificate2 cert)
{
    // based on sample code on https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509enhancedkeyusageextension
    foreach (X509Extension ext in cert.Extensions)
    {
        if (ext.Oid == null)
            continue;

        if (ext.Oid.FriendlyName == "Enhanced Key Usage")
        {
            var ext2 = (X509EnhancedKeyUsageExtension)ext;
            foreach (Oid oid in ext2.EnhancedKeyUsages)
            {
                if (oid.Value == "1.3.6.1.5.5.7.3.2") // clientAuth OID
                    return true;
            }
        }
    }
    return false;
}


string GetCertHash(CertType type)
{
    if (type == CertType.ActiveDirectory)
    {
        // Get long-lived 10-year "MS-Organization-Access" clientAuth certificate associated with a Active-Directory joined machine
        using RegistryKey key = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\CloudDomainJoin\\JoinInfo")!;
        var names = key.GetSubKeyNames();

        if (names.Length == 0)
            throw new ApplicationException("no AD clientAuth cert found");

        return names[0]; // use first AD connection
    } else if (type == CertType.InTune)
    {
        // Get short-lived 1-year "Microsoft Intune MDM Device CA" certificate
        using RegistryKey key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Provisioning\\OMADM\\Accounts")!;
        var names = key.GetSubKeyNames();

        if (names.Length == 0)
            throw new ApplicationException("no InTune clientAuth cert found");

        using RegistryKey subkey = key.OpenSubKey(names[0])!;

        var cert_ref = (string)subkey.GetValue("SslClientCertReference")!;
        var tokens = cert_ref.Split(";");
        Debug.Assert(tokens[0] == "MY");
        Debug.Assert(tokens[1] == "System");
        return tokens[2];
    }

    throw new ApplicationException("Unsupported CertType");
}


X509Certificate2 GetMachineCertificateFromHash (string cert_hash)
{
    using X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
    store.Open(OpenFlags.ReadOnly);

    // expired certs. are included in the enumeration
    foreach (X509Certificate2 cert in store.Certificates)
    {
        if (cert.GetCertHashString() != cert_hash)
            continue;

        // sanity checks
        Debug.Assert(cert.HasPrivateKey);
        Debug.Assert(IsClientAuthCertificate(cert));

        return cert;
    }

    throw new ApplicationException("no cert found");
}

/** Returns the first clientAuth certificate with private key found in the Windows cert. store. */
X509Certificate2 GetFirstClientAuthCert()
{
    // open personal certificate store
    using X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
    store.Open(OpenFlags.ReadOnly);

    // expired certs. are included in the enumeration
    foreach (X509Certificate2 cert in store.Certificates)
    {
        if (!cert.HasPrivateKey)
            continue;

        if (IsClientAuthCertificate(cert))
        {
            Console.WriteLine("Client certificate: " + cert.Subject + "\n");
            return cert;
        }
    }

    throw new ApplicationException("no clientAuth cert found");
}

string hostname = "localhost:443"; // default
if (args.Length > 0)
    hostname = args[0];

using HttpClientHandler handler = new HttpClientHandler();
{
    // client cert. selection
    if (args.Length > 1) {
        if (args[1] == "ad")
            handler.ClientCertificates.Add(GetMachineCertificateFromHash(GetCertHash(CertType.ActiveDirectory)));
        else if (args[1] == "intune")
            handler.ClientCertificates.Add(GetMachineCertificateFromHash(GetCertHash(CertType.InTune)));
    }
    if (handler.ClientCertificates.Count == 0)
        handler.ClientCertificates.Add(GetFirstClientAuthCert());
}
{
    // perform HTTP request with client authentication
    using HttpClient client = new HttpClient(handler);

    try
    {
        HttpResponseMessage response = await client.GetAsync("https://"+hostname);
        response.EnsureSuccessStatusCode();

        string responseBody = await response.Content.ReadAsStringAsync();
        Console.WriteLine(responseBody);
    }
    catch (Exception e)
    {
        Console.WriteLine("ERROR:{0} ", e.Message);
    }
}

enum CertType
{
    ActiveDirectory, /// long-lived 10 year "MS-Organization-Access"
    InTune,          /// short-lived 1-year "Microsoft Intune MDM Device CA" certificate
};