/** Sample code demonstrating how to retrieve proxy settings and perform per-URL proxy lookup.
    Most users probably want to use "netsh winhttp show advproxy" instead of this tool if on Win11 or newer. */
#include <iostream>
#include <cassert>
#include <shlobj_core.h>
#include "ProxyConfig.hpp"
#include "ProxySettings.hpp"
#include <winhttp.h>


void ProxyChangeCallback(ULONGLONG /*flags*/, void* context) {
    wprintf(L"\n");
    wprintf(L"\n");
    wprintf(L"UPDATE: Detected proxy settings change.\n");
    wprintf(L"\n");

    wchar_t* url = (wchar_t*)context;
    PrintProxySettings(url);
}

// WinHttpRegisterProxyChangeNotification function signature
typedef DWORD (*WinHttpRegisterProxyChangeNotification_fn)(ULONGLONG ullFlags, WINHTTP_PROXY_CHANGE_CALLBACK pfnCallback, PVOID pvContext, WINHTTP_PROXY_CHANGE_REGISTRATION_HANDLE* hRegistration);


int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        wprintf(L"USAGE: ProxyConfig.exe <URL>\n");
        return 1;
    }

    std::wstring url = argv[1]; // L"http://www.google.com/";

    if ((url == L"autoproxy") && (argc >= 3)) {
        std::wstring autoConfigUrl = argv[2];
        int res = UpdateProxySettings(autoConfigUrl.c_str(), nullptr, nullptr, true);

        if (IsUserAnAdmin())
            SetProxyPerUser(false);
        else
            wprintf(L"Skipping system-wide proxy configuration since user is not an admin.\n");

        return res;
    }else if ((url == L"setproxy") && (argc >= 4)) {
        std::wstring proxy = argv[2];
        std::wstring bypassList = argv[3];
        int res = UpdateProxySettings(nullptr, proxy.c_str(), bypassList.c_str(), true);

        if (IsUserAnAdmin())
            SetProxyPerUser(false);
        else
            wprintf(L"Skipping system-wide proxy configuration since user is not an admin.\n");

        return res;
    }

    PrintProxySettings(url.c_str());

    {
        // WinHttpRegisterProxyChangeNotification is not yet available on Win10 22H2. Therefore,
        // load the function pointer manually to avoid startup crash on older Windows versions.
        HMODULE winHttp = LoadLibrary(L"WinHttp.dll");
        assert(winHttp);
        auto winHttpRegisterProxyChangeNotification = (WinHttpRegisterProxyChangeNotification_fn)GetProcAddress(winHttp, "WinHttpRegisterProxyChangeNotification"); // not yet avialable on Win10 22H2

        if (winHttpRegisterProxyChangeNotification) {
            wprintf(L"Registering proxy change notification handler...\n");
            WINHTTP_PROXY_CHANGE_REGISTRATION_HANDLE handle = 0;
            DWORD err = winHttpRegisterProxyChangeNotification(WINHTTP_PROXY_NOTIFY_CHANGE, ProxyChangeCallback, (void*)url.c_str(), &handle);
            assert(!err);

            wprintf(L"Waiting for proxy setting changes...\n");
            Sleep(INFINITE);
        } else {
            wprintf(L"Unable to subscribe to proxy changes since WinHttpRegisterProxyChangeNotification is not available. ");
            wprintf(L"This is most likely caused by running on a Windows version predating Win11.\n");
        }
    }

    return 0;
}
