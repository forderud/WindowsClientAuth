#include "ProxyConfig.hpp"
#include <Windows.h>
#include <wininet.h>
#include <atlbase.h>
#include <cassert>
#include <vector>

#pragma comment(lib, "Wininet.lib")


int UpdateProxySettings(const wchar_t* autoConfigUrl, const wchar_t* proxyServer, const wchar_t* proxyBypass, bool autoDetect) {
    // bassed on https://www.powershellgallery.com/packages/WinInetProxy/0.1.0/Content/WinInetProxy.psm1
    wprintf(L"Updating proxy configuration for current user...\n");

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

    HINTERNET session = 0; // don't need to open handle
    BOOL ok = InternetSetOptionW(session, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, sizeof(list));
    if (!ok) {
        DWORD err = GetLastError();
        wprintf(L"InternetSetOption INTERNET_OPTION_PER_CONNECTION_OPTION failed with err %u\n", err);
        abort();
    }

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
        res = internetSettingsPolicy.SetDWORDValue(L"ProxySettingsPerUser", 0);
        res; // ignore errors

        CRegKey HKLM_internetSettings;
        res = HKLM_internetSettings.Open(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
        if (res != ERROR_SUCCESS) {
            wprintf(L"ERROR Unable to open HKLM Internet Settings (err=%u).\n", res);
            abort();
        }

        res = HKLM_internetSettings.SetDWORDValue(L"MigrateProxy", 1);
        res; // ignore errors

        wprintf(L"Proxy is system-wide.\n");
    } else {
        res = internetSettingsPolicy.DeleteSubKey(L"ProxySettingsPerUser");
        res; // ignore errors

        CRegKey HKCU_internetSettings;
        res = HKCU_internetSettings.Open(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
        if (res != ERROR_SUCCESS) {
            wprintf(L"ERROR Unable to open HKCU Internet Settings (err=%u).\n", res);
            abort();
        }

        res = HKCU_internetSettings.SetDWORDValue(L"MigrateProxy", 1);
        res; // ignore errors

        wprintf(L"Proxy is per user.\n");
    }

    return 0;
}
