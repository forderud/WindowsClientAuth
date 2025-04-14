/** Sample code demonstrating how to retrieve proxy settings and perform per-URL proxy lookup.
    Most users probably want to use "netsh winhttp show advproxy" instead of this tool if on Win11 or newer. */
#include <iostream>
#include <cassert>
#include <shlobj_core.h>
#include "ProxyConfig.hpp"
#include "ProxySettings.hpp"
#include <winhttp.h>
#include <atlbase.h>

//#define ENABLE_PROXY_CHANGE_NOTIFICATION


bool IsWin11OrNewer() {
    CRegKey reg;
    LSTATUS res = reg.Open(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", KEY_READ);
    assert(res == ERROR_SUCCESS);

    wchar_t buildStr[128] = {};
    ULONG charCount = std::size(buildStr);
    res = reg.QueryStringValue(L"CurrentBuild", buildStr, &charCount);
    assert(res == ERROR_SUCCESS);

    int buildNum = _wtoi(buildStr);
    return buildNum >= 22000;
}

#ifdef ENABLE_PROXY_CHANGE_NOTIFICATION
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
#endif


int wmain(int argc, wchar_t* argv[]) {
    if (IsWin11OrNewer()) {
        wprintf(L"WARNING: You should instead use netsh winhttp set advproxy if running on Win11 or newer.\n");
        wprintf(L"\n");
    }

    if (argc < 2) {
        wprintf(L"USAGE modes:\n");
        wprintf(L"  View proxy settings: ProxyConfig.exe view <test-url>\n");
        wprintf(L"  Set autoproxy PAC  : ProxyConfig.exe autoproxy <pac-url>\n");
        wprintf(L"  Set classic proxy  : ProxyConfig.exe setproxy <proxy> <bypass-list>\n");
        return 1;
    }

    std::wstring mode = argv[1];

    if ((mode == L"autoproxy") && (argc >= 3)) {
        if (!IsUserAnAdmin()) {
            wprintf(L"ERROR: Admin privileges required to change system-wide proxy settings.\n");
            return 2;
        }

        SetProxyPerUser(false);

        std::wstring autoConfigUrl = argv[2];
        int res = UpdateProxySettings(autoConfigUrl.c_str(), nullptr, nullptr, true);
        return res;
    } else if ((mode == L"setproxy") && (argc >= 4)) {
        if (!IsUserAnAdmin()) {
            wprintf(L"ERROR: Admin privileges required to change system-wide proxy settings.\n");
            return 2;
        }

        SetProxyPerUser(false);

        std::wstring proxy = argv[2];
        std::wstring bypassList = argv[3];
        int res = UpdateProxySettings(nullptr, proxy.c_str(), bypassList.c_str(), true);
        return res;
    } else if (mode == L"view") {
        wchar_t* url = nullptr;
        if (argc >= 3)
            url = argv[2]; // L"http://www.google.com/";

        PrintProxySettings(url);

        {
#ifdef ENABLE_PROXY_CHANGE_NOTIFICATION
            // WinHttpRegisterProxyChangeNotification is not yet available on Win10 22H2. Therefore,
            // load the function pointer manually to avoid startup crash on older Windows versions.
            HMODULE winHttp = LoadLibrary(L"WinHttp.dll");
            assert(winHttp);
            auto winHttpRegisterProxyChangeNotification = (WinHttpRegisterProxyChangeNotification_fn)GetProcAddress(winHttp, "WinHttpRegisterProxyChangeNotification"); // not yet avialable on Win10 22H2

            if (winHttpRegisterProxyChangeNotification) {
                wprintf(L"Registering proxy change notification handler...\n");
                WINHTTP_PROXY_CHANGE_REGISTRATION_HANDLE handle = 0;
                DWORD err = winHttpRegisterProxyChangeNotification(WINHTTP_PROXY_NOTIFY_CHANGE, ProxyChangeCallback, (void*)url, &handle);
                assert(!err);

                wprintf(L"Waiting for proxy setting changes...\n");
                Sleep(INFINITE);
            } else {
                wprintf(L"Unable to subscribe to proxy changes since WinHttpRegisterProxyChangeNotification is not available. ");
                wprintf(L"This is most likely caused by running on a Windows version predating Win11.\n");
            }
#endif
        }
    } else {
        wprintf(L"ERROR: Unsupported mode.\n");
        return -1;
    }

    return 0;
}
