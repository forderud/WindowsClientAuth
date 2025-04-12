#pragma once
/** RAII wrappers of some WinHTTP proxy datastructures. */
#include <Windows.h>
#include <winhttp.h>


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
