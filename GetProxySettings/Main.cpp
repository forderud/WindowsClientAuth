/** Sample code demonstrating how to retrieve proxy settings and perform per-URL proxy lookup.
    Most users probably want to use "netsh winhttp show advproxy" instead of this tool if on Win11 or newer. */
#include <iostream>
#include <cassert>
#include "ProxyStructs.hpp"
#include "ProxyConfig.hpp"

#pragma comment(lib, "Winhttp.lib")


bool PrintProxySettings(const wchar_t* url) {
    wprintf(L"Checking proxy settings for %s ...\n", url);

    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG_wrap settings;
    BOOL ok = WinHttpGetIEProxyConfigForCurrentUser(&settings);
    assert(ok);

    settings.Print(L"Proxy settings for current user");
    wprintf(L"\n");

    WINHTTP_AUTOPROXY_OPTIONS options{};
    {
        // based on https://github.com/dotnet/runtime/blob/main/src/libraries/System.Net.Http/src/System/Net/Http/SocketsHttpHandler/WinInetProxyHelper.cs
        options.dwFlags = (settings.fAutoDetect ? WINHTTP_AUTOPROXY_AUTO_DETECT : 0) | (settings.lpszAutoConfigUrl ? WINHTTP_AUTOPROXY_CONFIG_URL : 0);
        options.dwAutoDetectFlags = settings.fAutoDetect ? (WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A) : 0;
        options.lpszAutoConfigUrl = settings.lpszAutoConfigUrl;
        options.lpvReserved = 0;
        options.dwReserved = 0;
        options.fAutoLogonIfChallenged = false;
    }

    if (options.dwFlags & WINHTTP_AUTOPROXY_CONFIG_URL) {
        HINTERNET_wrap session(WinHttpOpen(/*user agent*/nullptr, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));

        WINHTTP_PROXY_INFO_wrap info;
        ok = WinHttpGetProxyForUrl(session, url, &options, &info);
        if (!ok) {
            DWORD err = GetLastError();

            if (err == ERROR_WINHTTP_LOGIN_FAILURE) {
                // retry with auto-login enabled
                // based on https://github.com/chromium/chromium/blob/main/components/winhttp/proxy_configuration.cc
                options.fAutoLogonIfChallenged = true;
                ok = WinHttpGetProxyForUrl(session, url, &options, &info);
                err = GetLastError();
            }

            if (err == ERROR_WINHTTP_AUTODETECTION_FAILED)
                wprintf(L"ERROR: WinHttpGetProxyForUrl ERROR_WINHTTP_AUTODETECTION_FAILED\n");
            else
                wprintf(L"ERROR: WinHttpGetProxyForUrl failed with error %u\n", err);
            return false;
        }

        info.Print(L"Proxy settings for URL");
        wprintf(L"\n");
    } else {
        wprintf(L"Skipping WinHttpGetProxyForUrl lookup, since AutoconfigUrl is disabled\n");
        wprintf(L"\n");
    }

    return true;
}


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
        wprintf(L"USAGE: GetProxySettings.exe <URL>\n");
        return 1;
    }

    std::wstring url = argv[1]; // L"http://www.google.com/";

    if ((url == L"autoproxy") && (argc >= 3)) {
        std::wstring autoConfigUrl = argv[2];
        return UpdateProxySettings(autoConfigUrl.c_str(), nullptr, nullptr, true);
    }else if ((url == L"setproxy") && (argc >= 4)) {
        std::wstring proxy = argv[2];
        std::wstring bypassList = argv[3];
        return UpdateProxySettings(nullptr, proxy.c_str(), bypassList.c_str(), true);
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
