#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Web.Http.Filters.h>
#include <winrt/Windows.Security.Cryptography.Certificates.h>

#include <iostream>

#pragma comment(lib, "windowsapp.lib")

using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Security::Cryptography::Certificates;
using namespace Windows::Web::Http;

static Certificate FindClientAuthCert() {
    // open personal certificate store
    Collections::IVectorView<Certificate> certs = CertificateStores::FindAllAsync().get();

    // search for cetificate with clientAuth EKU
    for (Certificate cert : certs) {
        for (hstring eku : cert.EnhancedKeyUsages()) {
            if (std::wstring(eku) == L"1.3.6.1.5.5.7.3.2") { // clientAuth OID
                std::wcout << L"Client certificate: " << std::wstring(cert.Subject()) << L"\n\n";
                return cert;
            }
        }
    }

    throw hresult_error(winrt::impl::error_fail, L"no clientAuth cert found");
}


int wmain(int argc, wchar_t* argv[]) {
    init_apartment();

    std::wstring hostname = L"localhost:443"; // default
    if (argc > 1)
        hostname = argv[1];

    try {
        Filters::HttpBaseProtocolFilter filter;
        filter.ClientCertificate(FindClientAuthCert());

        HttpClient client(filter);

        // async GET request
        HttpResponseMessage response = client.GetAsync(Uri(L"https://" + hostname)).get();
        response.EnsureSuccessStatusCode();

        hstring message(response.Content().ReadAsStringAsync().get());
        std::wcout << std::wstring(message);
    } catch (hresult_error const& ex) {
        std::wcerr << L"ERROR: " << std::wstring(ex.message()) << std::endl;
    }

    return 0;
}
