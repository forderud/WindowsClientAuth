#include <windows.h>
#include <wininet.h>

#include <cassert>
#include <iostream>
#include <string>

#pragma comment(lib, "Wininet.lib")

static void CHECK_WIN32(bool ok) {
    if (ok)
        return;

    DWORD err = GetLastError();
    // might be ERROR_INTERNET_INCORRECT_HANDLE_TYPE
    std::string message = "Win32 error " + std::to_string(err);
    throw std::runtime_error(message);
}

/** HINTERNET RAII wrapper. */
class HInetWrap {
public:
    HInetWrap(HINTERNET handle) : m_handle(handle) {
        CHECK_WIN32(handle);
    }
    ~HInetWrap() {
        InternetCloseHandle(m_handle);
    }

    operator HINTERNET() const {
        return m_handle;
    }

private:
    HINTERNET m_handle = nullptr;
};


void HttpGetWinINet(std::wstring hostname, const CERT_CONTEXT * clientCert) {
    // parse hostname & port
    size_t idx = hostname.find(':');
    INTERNET_PORT port = 443; // default
    if (idx != std::wstring::npos) {
        port = stoi(hostname.substr(idx + 1));
        hostname = hostname.substr(0, idx); // remove port suffix
    }

    // load WinINet
    HInetWrap inet = InternetOpenW(L"TestAgent", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);

    // configure server connection
    HInetWrap ses = InternetConnectW(inet, hostname.c_str(), port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);

    // configure HTTP request
    const DWORD flags = INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_SECURE; // enable TLS
    HInetWrap req = HttpOpenRequestW(ses, L"GET", L"/", NULL, L"", NULL, flags, NULL);

    // configure client certificate
    CHECK_WIN32(InternetSetOptionW(req, INTERNET_OPTION_CLIENT_CERT_CONTEXT, (void*)clientCert, sizeof(*clientCert)));

    // send HTTP request
    CHECK_WIN32(HttpSendRequestW(req, NULL, 0, NULL, 0));

    // write response to console
    DWORD buffer_len = 0;
    char  buffer[16 * 1024] = {}; // 16kB buffer
    CHECK_WIN32(InternetReadFile(req, reinterpret_cast<void*>(buffer), sizeof(buffer) - 1, &buffer_len));
    buffer[buffer_len] = 0; // add null-termination
    std::cout << buffer << '\n';
}
