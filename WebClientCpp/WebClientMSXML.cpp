#include <msxml6.h>
#include <wrl.h>
#include <winrt/base.h>

#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "msxml6.lib")

using namespace Microsoft::WRL;

class HttpRequest3Callback : public RuntimeClass<RuntimeClassFlags<ClassicCom>, IXMLHTTPRequest3Callback> {
public:
    HttpRequest3Callback() {
        m_event = CreateEventEx(NULL, NULL, CREATE_EVENT_MANUAL_RESET, EVENT_ALL_ACCESS);
    }

    ~HttpRequest3Callback() {
        if (m_event) {
            CloseHandle(m_event);
            m_event = nullptr;
        }
    }

    HRESULT OnRedirect(IXMLHTTPRequest2* pXHR, const WCHAR* pwszRedirectUrl) override {
        return S_OK;
    }

    HRESULT OnHeadersAvailable(IXMLHTTPRequest2* pXHR, DWORD dwStatus, const WCHAR* pwszStatus) override {
        // print HTTP status code
        std::wcout << L"STATUS " <<  dwStatus << L" " << pwszStatus << std::endl;
        return S_OK;
    }

    HRESULT OnDataAvailable(IXMLHTTPRequest2* pXHR, ISequentialStream* responseStream) override {
        for (;;) {
            char buffer[1024] = {};
            DWORD read = 0;
            HRESULT hr = responseStream->Read(buffer, (ULONG)std::size(buffer) - 1, &read);
            if (FAILED(hr) || read == 0)
                break;
            buffer[read] = 0; // add zero termination

            // print response to console
            std::cout << buffer << std::endl;
        }

        return S_OK;
    }

    HRESULT OnResponseReceived(IXMLHTTPRequest2* pXHR, ISequentialStream* pResponseStream) override {
        SetEvent(m_event); // signal completion
        return S_OK;
    }

    HRESULT OnError(IXMLHTTPRequest2* pXHR, HRESULT hrError) override {
        SetEvent(m_event); // signal completion
        return S_OK;
    }

    HRESULT OnServerCertificateReceived(IXMLHTTPRequest3* pXHR, DWORD dwCertErrors, DWORD cServerCertChain, const XHR_CERT* rgServerCertChain) override {
        return S_OK;
    }

    HRESULT OnClientCertificateRequested(IXMLHTTPRequest3* pXHR, DWORD cIssuerList, const WCHAR** rgpwszIssuerList) override {
        return S_OK;
    }

    /** Block until completion. */
    void Wait() {
        WaitForSingleObject(m_event, INFINITE);
    }

private:
    HANDLE m_event = nullptr;
};


void HttpGetMSXML6(std::wstring url, std::vector<uint8_t> certHash) {
    ComPtr<IXMLHTTPRequest3> http;
    HRESULT hr = CoCreateInstance(CLSID_FreeThreadedXMLHTTP60, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&http));
    if (FAILED(hr))
        throw winrt::hresult_error(hr);

    hr = http->SetClientCertificate((DWORD)certHash.size(), certHash.data(), NULL);
    if (FAILED(hr))
        throw winrt::hresult_error(hr);

    ComPtr<HttpRequest3Callback> cb;
    hr = MakeAndInitialize<HttpRequest3Callback>(&cb);
    if (FAILED(hr))
        throw winrt::hresult_error(hr);

    hr = http->Open(L"GET", url.c_str(), cb.Get(), NULL, NULL, NULL, NULL);
    if (FAILED(hr))
        throw winrt::hresult_error(hr);

    hr = http->Send(NULL, 0);
    if (FAILED(hr))
        throw winrt::hresult_error(hr);

    cb->Wait();
}
