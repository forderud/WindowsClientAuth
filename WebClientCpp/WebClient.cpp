#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Web.Http.Filters.h>
#include <winrt/Windows.Security.Cryptography.Certificates.h>

#include <iostream>

#pragma comment(lib, "windowsapp.lib")

void CertAccessWin32();
void HttpGetMSXML6(std::wstring url, std::vector<uint8_t> certHash);

using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Security::Cryptography::Certificates;
using namespace Windows::Web::Http;

/** Returns the first clientAuth certificate with private key found in the Windows cert. store. */
static Certificate GetFirstClientAuthCert() {
    CertificateQuery query;
    {
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


int wmain(int argc, wchar_t* argv[]) {
    init_apartment();

#ifdef ENABLE_LOW_LEVEL_IMPL
    CertAccessWin32();
#else
    std::wstring hostname = L"localhost:443"; // default
    if (argc > 1)
        hostname = argv[1];

    try {
        auto clientCert = GetFirstClientAuthCert();
#ifndef ENABLE_WINRT_IMPL
        com_array<uint8_t> hash = clientCert.GetHashValue();
        std::vector<uint8_t> certHash(hash.size(), 0);
        for (uint32_t i = 0; i < hash.size(); ++i)
            certHash[i] = hash[i];
        HttpGetMSXML6(L"https://" + hostname, certHash);
#else
        Filters::HttpBaseProtocolFilter filter;
        filter.ClientCertificate(clientCert);

        // perform HTTP request with client authentication
        HttpClient client(filter);

        HttpResponseMessage response = client.GetAsync(Uri(L"https://" + hostname)).get();
        response.EnsureSuccessStatusCode();

        hstring message(response.Content().ReadAsStringAsync().get());
        std::wcout << std::wstring(message);
#endif
    } catch (hresult_error const& ex) {
        std::wcerr << L"ERROR: " << std::wstring(ex.message()) << std::endl;
    }
#endif
    return 0;
}
