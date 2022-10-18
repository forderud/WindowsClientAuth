#include <windows.h>
#include <ncrypt.h>

#include <functional>
#include <iostream>
#include <cassert>


void OpenCNGKey(const wchar_t* providername, const wchar_t* keyname, DWORD legacyKeySpec) {
    NCRYPT_PROV_HANDLE provider = 0;
    SECURITY_STATUS status = NCryptOpenStorageProvider(&provider, providername, 0);
    if (status != ERROR_SUCCESS)
        abort();

    NCRYPT_KEY_HANDLE key = 0;
    status = NCryptOpenKey(provider, &key, keyname, legacyKeySpec, NCRYPT_SILENT_FLAG);
    if (status == NTE_BAD_KEYSET)
        abort();
    if (status != ERROR_SUCCESS)
        abort();

    std::wcout << L"  CNG key access succeeded\n";

#if 0
    DWORD size = 0;
    status = NCryptGetProperty(key, NCRYPT_NAME_PROPERTY, nullptr, 0, &size, 0);
    if (status == NTE_NOT_FOUND)
        continue;
    if (status != ERROR_SUCCESS)
        abort();
    std::vector<BYTE> cert;
    cert.resize(size);
    NCryptGetProperty(key, NCRYPT_NAME_PROPERTY, &cert[0], size, &size, 0);
#endif

    NCryptFreeObject(key);

    NCryptFreeObject(provider);
}


void OpenCertStore(const wchar_t storename[], bool perUser) {
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, perUser ? CERT_SYSTEM_STORE_CURRENT_USER : CERT_SYSTEM_STORE_LOCAL_MACHINE, storename);
    if (store == NULL)
        abort();

    const CERT_CONTEXT * cert = nullptr;
    while ((cert = CertEnumCertificatesInStore(store, cert)) != NULL) {
        // print certificate name
        wchar_t buffer[1024] = {};
        DWORD len = CertNameToStrW(cert->dwCertEncodingType, &cert->pCertInfo->Subject, CERT_SIMPLE_NAME_STR, buffer, (DWORD)std::size(buffer));
        assert(len > 0);
        std::wcout << L"Cert: " << buffer << L'\n';

        len = 0;
        if (!CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &len)) {
            DWORD err = GetLastError();
            if (err == CRYPT_E_NOT_FOUND)
                continue;

            abort();
        }
        std::vector<BYTE> prov_buf(len, 0);
        if (!CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, prov_buf.data(), &len)) {
            DWORD err = GetLastError();
            err;
            abort();
        }

        CRYPT_KEY_PROV_INFO* provider = (CRYPT_KEY_PROV_INFO*)prov_buf.data();
        std::wcout << L"  Provider: " << provider->pwszProvName << L'\n';
        std::wcout << L"  Container: " << provider->pwszContainerName << L'\n';

        if (provider->dwProvType != 0) {
            std::wcout << L"  Not a CNG type key\n";
            continue;
        }

        OpenCNGKey(provider->pwszProvName, provider->pwszContainerName, provider->dwKeySpec);
    }

    CertCloseStore(store, 0);
}


void CertAccessWin32() {
    OpenCertStore(L"My", true);
}
