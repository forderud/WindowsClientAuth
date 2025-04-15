#pragma once

namespace wininet {
    void PrintProxySettings();

    int UpdateProxySettings(const wchar_t* autoConfigUrl, const wchar_t* proxyServer, const wchar_t* proxyBypass, bool autoDetect);
}


void PrintProxyPerUser();

int SetProxyPerUser(bool perUser);
