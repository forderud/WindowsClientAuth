#include "WinHTTPSettings.hpp"
#include <Windows.h>
#include <winhttp.h>
#include <iostream>
#include <cassert>

#pragma comment(lib, "Winhttp.lib")


struct WINHTTP_CURRENT_USER_IE_PROXY_CONFIG_wrap : public WINHTTP_CURRENT_USER_IE_PROXY_CONFIG {
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG_wrap() {
        fAutoDetect = FALSE;
        lpszAutoConfigUrl = nullptr;
        lpszProxy = nullptr;
        lpszProxyBypass = nullptr;
    }

    ~WINHTTP_CURRENT_USER_IE_PROXY_CONFIG_wrap() {
        if (lpszAutoConfigUrl) {
            GlobalFree(lpszAutoConfigUrl);
            lpszAutoConfigUrl = nullptr;
        }
        if (lpszProxy) {
            GlobalFree(lpszProxy);
            lpszProxy = nullptr;
        }
        if (lpszProxyBypass) {
            GlobalFree(lpszProxyBypass);
            lpszProxyBypass = nullptr;
        }
    }

    void Print(const wchar_t* heading) const {
        wprintf(L"%s:\n", heading);
        wprintf(L"  Proxy auto detect: %s\n", fAutoDetect ? L"enabled" : L"disabled");
        wprintf(L"  Proxy auto config URL: %s\n", lpszAutoConfigUrl);
        wprintf(L"  Proxy server: %s\n", lpszProxy);
        wprintf(L"  Proxy bypass: %s\n", lpszProxyBypass);
    }
};
static_assert(sizeof(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG_wrap) == sizeof(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG), "WINHTTP_CURRENT_USER_IE_PROXY_CONFIG_wrap size mismatch");


struct WINHTTP_PROXY_INFO_wrap : public WINHTTP_PROXY_INFO {
    WINHTTP_PROXY_INFO_wrap() {
        dwAccessType = 0;
        lpszProxy = nullptr;
        lpszProxyBypass = nullptr;
    }

    ~WINHTTP_PROXY_INFO_wrap() {
        if (lpszProxy) {
            GlobalFree(lpszProxy);
            lpszProxy = nullptr;
        }
        if (lpszProxyBypass) {
            GlobalFree(lpszProxyBypass);
            lpszProxyBypass = nullptr;
        }
    }

    void Print(const wchar_t* heading) const {
        wprintf(L"%s:\n", heading);

        const wchar_t* type = nullptr;
        if (dwAccessType == WINHTTP_ACCESS_TYPE_NO_PROXY)
            type = L"NO_PROXY";
        else if (dwAccessType == WINHTTP_ACCESS_TYPE_DEFAULT_PROXY)
            type = L"DEFAULT_PROXY";
        else if (dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY)
            type = L"NAMED_PROXY";

        wprintf(L"  Proxy access type: %s\n", type);
        wprintf(L"  Proxy server: %s\n", lpszProxy);
        wprintf(L"  Proxy bypass: %s\n", lpszProxyBypass);
    }

};
static_assert(sizeof(WINHTTP_PROXY_INFO_wrap) == sizeof(WINHTTP_PROXY_INFO), "WINHTTP_PROXY_INFO_wrap size mismatch");


class HINTERNET_wrap {
public:
    HINTERNET_wrap(HINTERNET session) : m_session(session) {
        assert(m_session);
    }

    ~HINTERNET_wrap() {
        if (m_session) {
            WinHttpCloseHandle(m_session);
            m_session = 0;
        }
    }

    operator HINTERNET() {
        return m_session;
    }

private:
    HINTERNET m_session = 0;
};


bool winhttp::PrintProxySettings(const wchar_t* testUrl) {
    wprintf(L"Checking WinHttp proxy settings...\n");

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
