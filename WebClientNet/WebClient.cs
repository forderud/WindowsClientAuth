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

/** Return the long-lived 10 year "MS-Organization-Access" clientAuth certificate associated with a Active-Directory joined machine. */
X509Certificate2 GetActiveDirectoryCertificate ()
{
    string ad_cert_hash;
    { 
        using RegistryKey key = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\CloudDomainJoin\\JoinInfo")!;
        var names = key.GetSubKeyNames();

        if (names.Length == 0)
            throw new ApplicationException("no AD clientAuth cert found");

        ad_cert_hash = names[0]; // use first AD connection
    }

    using X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
    store.Open(OpenFlags.ReadOnly);

    // expired certs. are included in the enumeration
    foreach (X509Certificate2 cert in store.Certificates)
    {
        if (cert.GetCertHashString() != ad_cert_hash)
            continue;

        // sanity checks
        Debug.Assert(cert.HasPrivateKey);
        Debug.Assert(IsClientAuthCertificate(cert));

        return cert;
    }

    throw new ApplicationException("no AD clientAuth cert found");
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

{
    using HttpClientHandler handler = new HttpClientHandler();
#if true
    handler.ClientCertificates.Add(GetFirstClientAuthCert());
#else
    handler.ClientCertificates.Add(GetActiveDirectoryCertificate());
#endif

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
