#include <windows.h>
#include <wininet.h>

#include <cassert>
#include <iostream>
#include <string>

#pragma comment(lib, "Wininet.lib")


void HttpGetWinINet(std::wstring hostname, const CERT_CONTEXT * clientCert) {
    // parse hostname & port
    size_t idx = hostname.find(':');
    INTERNET_PORT port = 443; // default
    if (idx != std::wstring::npos) {
        port = stoi(hostname.substr(idx + 1));
        hostname = hostname.substr(0, idx); // remove port suffix
    }

    HINTERNET inet = InternetOpenW(L"TestAgent", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!inet)
        abort();

    HINTERNET ses = InternetConnectW(inet, hostname.c_str(), port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!ses)
        abort();

    const DWORD flags = INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_SECURE; // enable TLS
    HINTERNET req = HttpOpenRequestW(ses, L"GET", L"/", NULL, L"", NULL, flags, NULL);
    if (!req)
        abort();

    BOOL ok = InternetSetOptionW(req, INTERNET_OPTION_CLIENT_CERT_CONTEXT, (void*)clientCert, sizeof(*clientCert));
    if (!ok) {
        DWORD err = GetLastError();
        // might be ERROR_INTERNET_INCORRECT_HANDLE_TYPE
        abort();
    }

    int result = HttpSendRequest(req, NULL, 0, NULL, 0);
    assert(result == 1);

    DWORD buffer_len = 0;
    char  buffer[16 * 1024] = {}; // 16kB buffer
    InternetReadFile(req, reinterpret_cast<void*>(buffer), sizeof(buffer) - 1, &buffer_len);
    buffer[buffer_len] = 0; // add null-termination
    std::cout << buffer << '\n';

    InternetCloseHandle(req);
    InternetCloseHandle(ses);
    InternetCloseHandle(inet);
}
