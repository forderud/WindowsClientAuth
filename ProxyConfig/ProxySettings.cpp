#include "ProxySettings.hpp"
#include "ProxyStructs.hpp"

#pragma comment(lib, "Winhttp.lib")


bool PrintProxySettings(const wchar_t* testUrl) {
    wprintf(L"Checking proxy settings for %s ...\n", testUrl);

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

    if (testUrl && (options.dwFlags & WINHTTP_AUTOPROXY_CONFIG_URL)) {
        HINTERNET_wrap session(WinHttpOpen(/*user agent*/nullptr, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));

        WINHTTP_PROXY_INFO_wrap info;
        ok = WinHttpGetProxyForUrl(session, testUrl, &options, &info);
        if (!ok) {
            DWORD err = GetLastError();

            if (err == ERROR_WINHTTP_LOGIN_FAILURE) {
                // retry with auto-login enabled
                // based on https://github.com/chromium/chromium/blob/main/components/winhttp/proxy_configuration.cc
                options.fAutoLogonIfChallenged = true;
                ok = WinHttpGetProxyForUrl(session, testUrl, &options, &info);
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
        wprintf(L"Skipping WinHttpGetProxyForUrl lookup, since AutoconfigUrl is disabled or no url provided\n");
        wprintf(L"\n");
    }

    return true;
}
