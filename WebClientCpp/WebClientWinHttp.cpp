#include <winrt/base.h>
#include <atlbase.h>
#include "HttpRequest_h.h" // locally generated

#include <iostream>
#include <string>

using namespace winrt;


void HttpGetWinHttp(std::wstring url, std::wstring certName) {
    CComPtr<IWinHttpRequest> http;
    check_hresult(http.CoCreateInstance(CLSID_WinHttpRequest));

    check_hresult(http->SetClientCertificate(CComBSTR(certName.c_str())));
    
    CComVariant var_false(false); // VARIANT_FALSE;
    check_hresult(http->Open(CComBSTR(L"GET"), CComBSTR(url.c_str()), var_false/*not async*/));

    CComVariant var_empty; // empty payload
    check_hresult(http->Send(var_empty));

    CComBSTR response;
    check_hresult(http->get_ResponseText(&response));
    std::wcout << (BSTR)response << L'\n';
}
