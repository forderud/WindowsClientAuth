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
            X509EnhancedKeyUsageExtension ext2 = (X509EnhancedKeyUsageExtension)ext;
            foreach (Oid oid in ext2.EnhancedKeyUsages)
            {
                if (oid.Value == "1.3.6.1.5.5.7.3.2") // clientAuth OID
                    return true;
            }
        }
    }
    return false;
}


X509Certificate2 GetClientCertificate()
{
    // open personal certificate store
    using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
    {
        store.Open(OpenFlags.ReadOnly);

        foreach (X509Certificate2 cert in store.Certificates)
        {
            if (IsClientAuthCertificate(cert))
            {
                Console.WriteLine("Client certificate: " + cert.Subject + "\n");
                return cert;
            }
        }
    }

    throw new ApplicationException("no clientAuth cert found");
}

string hostname = "localhost:443"; // default
if (args.Length > 0)
    hostname = args[0];

using (HttpClientHandler handler = new HttpClientHandler())
{
    handler.UseDefaultCredentials = true;

    // populate handler.ClientCertificates list
    handler.ClientCertificates.Add(GetClientCertificate());

    // perform HTTP request with client authentication
    using (HttpClient client = new HttpClient(handler))
    {
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
}
