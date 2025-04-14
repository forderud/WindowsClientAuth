#include "ProxyConfig.hpp"
#include <Windows.h>
#include <wininet.h>
#include <atlbase.h>
#include <cassert>
#include <vector>

#pragma comment(lib, "Wininet.lib")


const wchar_t* InternetPerConString(DWORD dwOption) {
    switch (dwOption) {
    case INTERNET_PER_CONN_FLAGS:
        return L"INTERNET_PER_CONN_FLAGS";
    case INTERNET_PER_CONN_PROXY_SERVER:
        return L"INTERNET_PER_CONN_PROXY_SERVER";
    case INTERNET_PER_CONN_PROXY_BYPASS:
        return L"INTERNET_PER_CONN_PROXY_BYPASS";
    case INTERNET_PER_CONN_AUTOCONFIG_URL:
        return L"INTERNET_PER_CONN_AUTOCONFIG_URL";
    case INTERNET_PER_CONN_AUTODISCOVERY_FLAGS:
        return L"INTERNET_PER_CONN_AUTODISCOVERY_FLAGS";
    case INTERNET_PER_CONN_AUTOCONFIG_SECONDARY_URL:
        return L"INTERNET_PER_CONN_AUTOCONFIG_SECONDARY_URL";
    case INTERNET_PER_CONN_AUTOCONFIG_RELOAD_DELAY_MINS:
        return L"INTERNET_PER_CONN_AUTOCONFIG_RELOAD_DELAY_MINS";
    case INTERNET_PER_CONN_AUTOCONFIG_LAST_DETECT_TIME:
        return L"INTERNET_PER_CONN_AUTOCONFIG_LAST_DETECT_TIME";
    case INTERNET_PER_CONN_AUTOCONFIG_LAST_DETECT_URL:
        return L"INTERNET_PER_CONN_AUTOCONFIG_LAST_DETECT_URL";
    case INTERNET_PER_CONN_FLAGS_UI:
        return L"INTERNET_PER_CONN_FLAGS_UI";
    }

    abort();
}

bool IsStringOption(DWORD dwOption) {
    if (dwOption == INTERNET_PER_CONN_PROXY_SERVER)
        return true;
    if (dwOption == INTERNET_PER_CONN_PROXY_BYPASS)
        return true;
    if (dwOption == INTERNET_PER_CONN_AUTOCONFIG_URL)
        return true;
    if (dwOption == INTERNET_PER_CONN_AUTOCONFIG_SECONDARY_URL)
        return true;
    if (dwOption == INTERNET_PER_CONN_AUTOCONFIG_LAST_DETECT_URL)
        return true;

    return false;
}


void PrintProxySettings() {
    std::vector<INTERNET_PER_CONN_OPTIONW> options(4, INTERNET_PER_CONN_OPTIONW{});
    options[0].dwOption = INTERNET_PER_CONN_FLAGS_UI;
    options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
    options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    options[3].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;

    INTERNET_PER_CONN_OPTION_LISTW list{};
    {
        list.dwSize = sizeof(list);
        list.pszConnection = NULL; // LAN
        list.dwOptionCount = (DWORD)options.size();
        list.pOptions = options.data();
    }

    HINTERNET session = NULL; // 0 means system-wide changes
    DWORD bufferSize = sizeof(list);
    BOOL ok = InternetQueryOptionW(session, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &bufferSize);
    if (!ok) {
        DWORD err = GetLastError();
        wprintf(L"InternetQueryOptionW INTERNET_OPTION_PER_CONNECTION_OPTION failed with err %u\n", err);
        abort();
    }

    for (DWORD i = 0; i < list.dwOptionCount; i++) {
        INTERNET_PER_CONN_OPTIONW& option = list.pOptions[i];

        wprintf(L"Option #%u:\n", i);
        wprintf(L"  Type: %s\n", InternetPerConString(option.dwOption));

        if (option.dwOption == INTERNET_PER_CONN_FLAGS_UI) {
            // integer values
            wprintf(L"  Value:");
            if (option.Value.dwValue & PROXY_TYPE_DIRECT)
                wprintf(L" | PROXY_TYPE_DIRECT");
            if (option.Value.dwValue & PROXY_TYPE_PROXY)
                wprintf(L" | PROXY_TYPE_PROXY");
            if (option.Value.dwValue & PROXY_TYPE_AUTO_PROXY_URL)
                wprintf(L" | PROXY_TYPE_AUTO_PROXY_URL");
            if (option.Value.dwValue & PROXY_TYPE_AUTO_DETECT)
                wprintf(L" | PROXY_TYPE_AUTO_DETECT");
            wprintf(L"\n");
        } else if (IsStringOption(option.dwOption)) {
            // string-based values
            wprintf(L"  Value: %s\n", option.Value.pszValue);
        }
    }
}


int UpdateProxySettings(const wchar_t* autoConfigUrl, const wchar_t* proxyServer, const wchar_t* proxyBypass, bool autoDetect) {
    // bassed on https://www.powershellgallery.com/packages/WinInetProxy/0.1.0/Content/WinInetProxy.psm1
    wprintf(L"Updating proxy configuration...\n");

    std::vector<INTERNET_PER_CONN_OPTIONW> options(4, INTERNET_PER_CONN_OPTIONW{});
    {
        // DOC: https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_optionw
        options[0].dwOption = INTERNET_PER_CONN_FLAGS_UI;
        DWORD& proxyType = options[0].Value.dwValue;
        proxyType = PROXY_TYPE_DIRECT;

        if (autoDetect)
            proxyType |= PROXY_TYPE_AUTO_DETECT;
        wprintf(L"  AutoDetect: %s\n", autoDetect ? L"Enabled" : L"Disabled");

        options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
        if (proxyServer) {
            wprintf(L"  Proxy: %s\n", proxyServer);
            proxyType |= PROXY_TYPE_PROXY;
            options[1].Value.pszValue = (wchar_t*)proxyServer;
        }

        options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
        if (proxyBypass) {
            wprintf(L"  ProxyBypass: %s\n", proxyBypass);
            options[2].Value.pszValue = (wchar_t*)proxyBypass;
        }

        options[3].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
        if (autoConfigUrl) {
            wprintf(L"  AutoConfigURL: %s\n", autoConfigUrl);
            proxyType |= PROXY_TYPE_AUTO_PROXY_URL;
            options[3].Value.pszValue = (wchar_t*)autoConfigUrl;
        }
    }

    INTERNET_PER_CONN_OPTION_LISTW list{};
    {
        list.dwSize = sizeof(list);
        list.pszConnection = NULL; // LAN
        list.dwOptionCount = (DWORD)options.size();
        list.pOptions = options.data();
    }

    HINTERNET session = NULL; // 0 means system-wide changes

    // configure new proxy settings
    BOOL ok = InternetSetOptionW(session, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, sizeof(list));
    if (!ok) {
        DWORD err = GetLastError();
        wprintf(L"InternetSetOption INTERNET_OPTION_PER_CONNECTION_OPTION failed with err %u\n", err);
        abort();
    }
    // refresh global proxy settings
    ok = InternetSetOptionW(session, INTERNET_OPTION_REFRESH, nullptr, 0);
    if (!ok) {
        DWORD err = GetLastError();
        wprintf(L"InternetSetOption INTERNET_OPTION_REFRESH failed with err %u\n", err);
        abort();
    }

    wprintf(L"[completed]\n");
    return 0;
}


int SetProxyPerUser(bool perUser) {
    // based on https://www.powershellgallery.com/packages/WinInetProxy/0.1.0/Content/WinInetProxy.psm1
    CRegKey internetSettingsPolicy;
    LSTATUS res = internetSettingsPolicy.Open(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
    if (res != ERROR_SUCCESS) {
        wprintf(L"ERROR Unable to open HKLM Policies Internet Settings (err=%u).\n", res);
        abort();
    }

    if (!perUser) {
        // enable system-wide proxy settings
        res = internetSettingsPolicy.SetDWORDValue(L"ProxySettingsPerUser", 0);
        res; // ignore errors

        wprintf(L"Proxy settings are system-wide.\n");
    } else {
        // disable system-wide proxy settings
        res = internetSettingsPolicy.DeleteValue(L"ProxySettingsPerUser");
        res; // ignore errors

        wprintf(L"Proxy settings are per user.\n");
    }

    return 0;
}
