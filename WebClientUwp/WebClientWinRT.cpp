#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Web.Http.Filters.h>
#include <winrt/Windows.Security.Cryptography.Certificates.h>
#include <iostream>

#pragma comment(lib, "windowsapp.lib")

using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Security::Cryptography::Certificates;
using namespace Windows::Web::Http;

/** Returns the first clientAuth certificate with private key found in the Windows cert. store. */
Certificate GetFirstClientAuthCert() {
    CertificateQuery query;
    {
        query.IncludeExpiredCertificates(false);

        Collections::IVector<hstring> eku = query.EnhancedKeyUsages();
        eku.Append(L"1.3.6.1.5.5.7.3.2"); // clientAuth OID

        query.StoreName(StandardCertificateStoreNames::Personal()); // "MY" store for current user (default)
    }

    // search for first matching certificate
    Collections::IVectorView<Certificate> certs = CertificateStores::FindAllAsync(query).get();
    for (Certificate cert : certs) {
        if (!cert.HasPrivateKey())
            continue;

        std::wcout << L"Client certificate: " << std::wstring(cert.Subject()) << L"\n\n";
        return cert;
    }

    throw hresult_error(winrt::impl::error_fail, L"no clientAuth cert found");
}


void HttpGetWinRT(std::wstring url, Certificate clientCert) {
    Filters::HttpBaseProtocolFilter filter;
    filter.ClientCertificate(clientCert);

    // perform HTTP request with client authentication
    HttpClient client(filter);

    HttpResponseMessage response = client.GetAsync(Uri(url)).get();
    response.EnsureSuccessStatusCode();

    hstring message(response.Content().ReadAsStringAsync().get());
    std::wcout << std::wstring(message);
}


int wmain(int argc, wchar_t* argv[]) {
    init_apartment();

    std::wstring hostname = L"localhost:443"; // default
    if (argc > 1)
        hostname = argv[1];

    try {
        auto clientCert = GetFirstClientAuthCert();

        std::wcout << "\n\nHTTP request using WinRT HttpClient:\n";
        HttpGetWinRT(L"https://" + hostname, clientCert);
    }
    catch (hresult_error const& ex) {
        std::wcerr << L"ERROR: " << std::wstring(ex.message()) << std::endl;
    }
    return 0;
}
