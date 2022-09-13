using System.Security.Cryptography.X509Certificates;


// open personal certificate store
X509Certificate2Collection GetClientCertificates()
{
    using (X509Store store = new X509Store(StoreName.My))
    {
        store.Open(OpenFlags.ReadOnly);

        Console.WriteLine("My store certificates:");
        foreach (X509Certificate cert in store.Certificates)
            Console.WriteLine("* Certificate: " + cert.Subject);

        return store.Certificates;
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
