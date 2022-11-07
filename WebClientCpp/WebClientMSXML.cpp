#include <msxml6.h>
#include <wrl.h>
#include <winrt/base.h>

#include <iostream>
#include <string>

#pragma comment(lib, "msxml6.lib")

using namespace winrt;

class HttpRequestCb : public implements<HttpRequestCb, IXMLHTTPRequest3Callback> {
public:
    HttpRequestCb() {
        m_event = CreateEventEx(NULL, NULL, CREATE_EVENT_MANUAL_RESET, EVENT_ALL_ACCESS);
    }

    ~HttpRequestCb() override {
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
        std::cout << "STATUS " <<  dwStatus << " " << pwszStatus << std::endl;
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
        m_hr = hrError;
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
    HRESULT Wait() {
        WaitForSingleObject(m_event, INFINITE);
        return m_hr;
    }

private:
    HRESULT m_hr = S_OK;
    HANDLE m_event = nullptr;
};


void HttpGetMSXML6(std::wstring url, const std::vector<uint8_t>& thumbprint) {
    com_ptr<IXMLHTTPRequest3> http;
    check_hresult(CoCreateInstance(CLSID_FreeThreadedXMLHTTP60, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(http.put())));

    check_hresult(http->SetClientCertificate((DWORD)thumbprint.size(), thumbprint.data(), NULL));

    com_ptr<HttpRequestCb> cb = make_self<HttpRequestCb>();

    check_hresult(http->Open(L"GET", url.c_str(), cb.get(), NULL, NULL, NULL, NULL));

    check_hresult(http->Send(NULL, 0));

    check_hresult(cb->Wait());
}
