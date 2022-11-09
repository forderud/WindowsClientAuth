#include <winrt/base.h>
#include <algorithm>
#include <iostream>
#include "CertAccess.hpp"

#pragma comment(lib, "windowsapp.lib")

using namespace winrt;

void HttpGetWinHttp(std::wstring url, std::wstring certName);
void HttpGetWinINet(std::wstring url, const CERT_CONTEXT* clientCert);
void HttpGetMSXML6(std::wstring url, const std::vector<uint8_t>& thumbprint);


int wmain(int argc, wchar_t* argv[]) {
    init_apartment();

    std::wstring hostname = L"localhost:443"; // default
    if (argc > 1)
        hostname = argv[1];

    const std::wstring storeName = L"My";
    const bool perUser = true;
    try {
        CertStore store(storeName.c_str(), perUser);

        for (auto it = store.Next(); it; it = store.Next()) {
            Certificate cert(it);
            std::wcout << L"Cert: " << cert.Name(CERT_SIMPLE_NAME_STR) << L'\n';

            if (cert.WillExpireInDays(31))
                std::wcout << L"  Cert will expire within a month.\n";

            std::wcout << L"  Thumbprint: " << cert.ThumbPrintHex() << L'\n';

            std::vector<std::string> ekus = cert.EnhancedKeyUsage(0);
#if 0
            for (auto eku : ekus)
                std::cout << "  EKU: " << eku << '\n';

            CRYPT_KEY_PROV_INFO* priv_key = cert.PrivateKey();
            if (!priv_key)
                continue;

            std::wcout << L"  Provider: " << priv_key->pwszProvName << L'\n';
            std::wcout << L"  Container: " << priv_key->pwszContainerName << L'\n';

            if (priv_key->dwProvType != 0) {
                std::wcout << L"  Not a CNG type key\n";
            } else {
                CNGKey cng(priv_key->pwszProvName, priv_key->pwszContainerName, priv_key->dwKeySpec);
                cng.Property(NCRYPT_NAME_PROPERTY);
                std::wcout << L"  CNG key access succeeded\n";
            }
#endif

            auto it2 = std::find(ekus.begin(), ekus.end(), std::string("1.3.6.1.5.5.7.3.2")); // clientAuth OID
            if (it2 == ekus.end())
                continue; // not a clientAuth certificate

            std::wcout << "  HTTP request using WinHttp:\n";
            HttpGetWinHttp(L"https://" + hostname, (perUser ? L"CURRENT_USER\\" : L"LOCAL_MACHINE\\") + storeName + L'\\' + cert.Name(CERT_SIMPLE_NAME_STR));
            std::wcout << "\n\n";

            std::wcout << "  HTTP request using WinINet:\n";
            HttpGetWinINet(hostname, cert);
            std::wcout << "\n\n";

            std::wcout << "  HTTP request using MSXML6:\n";
            std::vector<BYTE> thumbprint = cert.ContextProperty(CERT_HASH_PROP_ID);
            HttpGetMSXML6(L"https://" + hostname, thumbprint);
        }
    } catch (hresult_error const& ex) {
        std::wcerr << L"ERROR: " << std::wstring(ex.message()) << std::endl;
    } catch (std::exception const& ex) {
        std::cerr << "ERROR: " << ex.what() << std::endl;
    }
    return 0;
}
