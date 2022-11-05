#include <winrt/Windows.Security.Cryptography.Certificates.h>
#include <iostream>
using namespace winrt;
using namespace Windows::Security::Cryptography::Certificates;

void CertAccessWin32();
void HttpGetMSXML6(std::wstring url, const com_array<uint8_t>& thumbprint);
Certificate GetFirstClientAuthCert();
void HttpGetWinRT(std::wstring url, Certificate clientCert);


int wmain(int argc, wchar_t* argv[]) {
    init_apartment();

#ifdef ENABLE_LOW_LEVEL_IMPL
    CertAccessWin32();
    return 0;
#endif
    std::wstring hostname = L"localhost:443"; // default
    if (argc > 1)
        hostname = argv[1];

    std::wstring url = L"https://" + hostname;

    try {
        auto clientCert = GetFirstClientAuthCert();

        std::wcout << "HTTP request using MSXML6:\n";
        com_array<uint8_t> thumbprint = clientCert.GetHashValue(); // shown as "Thumbprint" in Windows cert. manager
        HttpGetMSXML6(url, thumbprint);
        
        std::wcout << "\n\nHTTP request using WinRT HttpClient:\n";
        HttpGetWinRT(url, clientCert);
    }
    catch (hresult_error const& ex) {
        std::wcerr << L"ERROR: " << std::wstring(ex.message()) << std::endl;
    }
    return 0;
}
