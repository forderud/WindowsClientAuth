#include <windows.h>
#include <wininet.h>
#include <winrt/base.h>
#include <wrl/wrappers/corewrappers.h>

#include <cassert>
#include <iostream>
#include <string>

#pragma comment(lib, "Wininet.lib")

/** HINTERNET RAII wrapper. */
struct InternetTraits {
    using Type = HINTERNET;
    static bool Close(_In_ Type h) noexcept {
        return InternetCloseHandle(h) != FALSE;
    };
    static Type GetInvalidValue() noexcept { return nullptr; };
};
using InternetHandle = Microsoft::WRL::Wrappers::HandleT<InternetTraits>;

using namespace winrt;


/** InternetReadFile wrapper. */
static std::string InternetReadFileWrap(HINTERNET req) {
    // TODO: Get rid of hardcoded buffer limit
    DWORD buffer_len = 0;
    char  buffer[16 * 1024] = {}; // 16kB buffer
    check_bool(InternetReadFile(req, reinterpret_cast<void*>(buffer), sizeof(buffer) - 1, &buffer_len));
    buffer[buffer_len] = 0; // add null-termination
    return buffer;
}

void HttpGetWinINet(std::wstring hostname, const CERT_CONTEXT * clientCert) {
    // parse hostname & port
    size_t idx = hostname.find(':');
    INTERNET_PORT port = 443; // default
    if (idx != std::wstring::npos) {
        port = stoi(hostname.substr(idx + 1));
        hostname = hostname.substr(0, idx); // remove port suffix
    }

    // load WinINet
    InternetHandle inet(InternetOpenW(L"TestAgent", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0));
    check_bool(inet.IsValid());

    // configure server connection
    InternetHandle ses(InternetConnectW(inet.Get(), hostname.c_str(), port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0));
    check_bool(ses.IsValid());

    // configure HTTP request
    const DWORD flags = INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_SECURE; // enable TLS
    InternetHandle req(HttpOpenRequestW(ses.Get(), L"GET", L"/", NULL, L"", NULL, flags, NULL));
    check_bool(req.IsValid());

    // configure client certificate
    check_bool(InternetSetOptionW(req.Get(), INTERNET_OPTION_CLIENT_CERT_CONTEXT, (void*)clientCert, sizeof(*clientCert)));

    // send HTTP request
    check_bool(HttpSendRequestW(req.Get(), NULL, 0, NULL, 0));

    // write response to console
    std::cout << InternetReadFileWrap(req.Get()) << '\n';
}
