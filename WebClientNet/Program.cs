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
                {
                    //Console.WriteLine("Certificate: " + cert.Subject);
                    return true;
                }
            }
        }
    }
    return false;
}


// open personal certificate store
X509Certificate2Collection GetClientCertificates()
{
    using (X509Store store = new X509Store(StoreName.My))
    {
        store.Open(OpenFlags.ReadOnly);

        Console.WriteLine("My client certificates:");
        var clientCerts = new X509Certificate2Collection();

        foreach (X509Certificate2 cert in store.Certificates)
        {
            if (IsClientAuthCertificate(cert))
            {
                Console.WriteLine("* Certificate: " + cert.Subject);
                clientCerts.Add(cert);
            }
        }
        Console.WriteLine();

        return clientCerts;
    }
}


using (HttpClientHandler handler = new HttpClientHandler())
{
    handler.UseDefaultCredentials = true;

    // populate handler.ClientCertificates list
    foreach (X509Certificate cert in GetClientCertificates())
        handler.ClientCertificates.Add(cert);

    // perform HTTP request with client authentication
    using (HttpClient client = new HttpClient(handler))
    {
        try
        {
            HttpResponseMessage response = await client.GetAsync("https://localhost:4443/");
            response.EnsureSuccessStatusCode();

            string responseBody = await response.Content.ReadAsStringAsync();
            Console.WriteLine(responseBody);
        }
        catch (HttpRequestException e)
        {
            Console.WriteLine("ERROR:{0} ", e.Message);
        }
    }
}
