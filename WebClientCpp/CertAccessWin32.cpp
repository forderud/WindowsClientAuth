#include <windows.h>
#include <ncrypt.h>

#include <functional>
#include <iostream>
#include <cassert>


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

        // CERT_NCRYPT_KEY_HANDLE_TRANSFER_PROP_ID
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
        std::wcout << L"  Container: " << provider->pwszContainerName << L'\n';
        std::wcout << L"  Provider: " << provider->pwszProvName << L'\n';
    }

    CertCloseStore(store, 0);
}


/** Low-level CNG key access.
    NOTICE: Cetificate access not yet impl. */
void EnumCNGKeys () {
    NCRYPT_PROV_HANDLE provider = 0;
    SECURITY_STATUS status = NCryptOpenStorageProvider(&provider, MS_KEY_STORAGE_PROVIDER, 0); // or MS_PLATFORM_CRYPTO_PROVIDER for TPM
    if (status != ERROR_SUCCESS)
        abort();

    NCryptKeyName* keyname = nullptr; // CNG key entry
    PVOID pos = nullptr;
    while (NCryptEnumKeys(provider, NULL, &keyname, &pos, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS) {
        std::wcout << L"Key: " << keyname->pszName << L'\n';

        NCRYPT_KEY_HANDLE key = 0;
        status = NCryptOpenKey(provider, &key, keyname->pszName, keyname->dwLegacyKeySpec, NCRYPT_SILENT_FLAG);
        if (status == NTE_BAD_KEYSET)
            abort();
        if (status != ERROR_SUCCESS)
            abort();

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

        NCryptFreeBuffer(keyname);
        keyname = nullptr;
    }
    NCryptFreeBuffer(pos);

    NCryptFreeObject(provider);
}


void CertAccessWin32() {
    OpenCertStore(L"My", true);
    EnumCNGKeys();
}
