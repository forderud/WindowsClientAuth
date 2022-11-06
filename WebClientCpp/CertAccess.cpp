#include "CertAccess.hpp"
#include <iostream>


class CNGKey {
public:
    CNGKey(const wchar_t* providername, const wchar_t* keyname, DWORD legacyKeySpec) {
        SECURITY_STATUS status = NCryptOpenStorageProvider(&m_provider, providername, 0);
        if (status != ERROR_SUCCESS)
            abort();

        status = NCryptOpenKey(m_provider, &m_key, keyname, legacyKeySpec, NCRYPT_SILENT_FLAG);
        if (status == NTE_BAD_KEYSET)
            abort();
        if (status != ERROR_SUCCESS)
            abort();

        std::wcout << L"  CNG key access succeeded\n";
    }
    ~CNGKey() {
        NCryptFreeObject(m_key);
        NCryptFreeObject(m_provider);
    }

    std::vector<BYTE> Property(const wchar_t* prop) const {
        DWORD size = 0;
        SECURITY_STATUS status = NCryptGetProperty(m_key, prop, nullptr, 0, &size, 0);
        if (status == NTE_NOT_FOUND)
            return {};
        if (status != ERROR_SUCCESS)
            abort();
        std::vector<BYTE> result;
        result.resize(size);
        NCryptGetProperty(m_key, prop, result.data(), size, &size, 0);
        return result;
    }

private:
    NCRYPT_PROV_HANDLE m_provider = 0;
    NCRYPT_KEY_HANDLE m_key = 0;
};


void CertAccessWin32() {
    CertStore store(L"My", true);

    for (auto it = store.Next(); it; it = store.Next()) {
        Certificate cert(it);
        std::wcout << L"Cert: " << cert.Name(CERT_SIMPLE_NAME_STR) << L'\n';

        if (cert.WillExpireInDays(31))
            std::wcout << L"  Cert will expire within a month.\n";

        std::wcout << L"  Thumbprint: " << cert.ThumbPrintHex() << L'\n';

        std::vector<std::string> ekus = cert.EnhancedKeyUsage(0);
        for (auto eku : ekus)
            std::cout << "  EKU: " << eku << '\n';

        CRYPT_KEY_PROV_INFO* priv_key = cert.PrivateKey();
        if (!priv_key)
            continue;

        std::wcout << L"  Provider: " << priv_key->pwszProvName << L'\n';
        std::wcout << L"  Container: " << priv_key->pwszContainerName << L'\n';

        if (priv_key->dwProvType != 0) {
            std::wcout << L"  Not a CNG type key\n";
            continue;
        }

        CNGKey cng(priv_key->pwszProvName, priv_key->pwszContainerName, priv_key->dwKeySpec);
        cng.Property(NCRYPT_NAME_PROPERTY);
    }
}
