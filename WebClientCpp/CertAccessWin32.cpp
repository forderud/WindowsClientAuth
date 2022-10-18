#include <windows.h>
#include <ncrypt.h>

#include <functional>
#include <iostream>


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
    EnumCNGKeys();
}
