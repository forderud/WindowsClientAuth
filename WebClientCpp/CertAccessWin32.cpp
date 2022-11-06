#include <windows.h>
#include <ncrypt.h>

#include <functional>
#include <iostream>
#include <cassert>


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

    std::vector<BYTE> Property(const wchar_t * prop) const {
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


class Certificate {
public:
    Certificate(const CERT_CONTEXT* cert) : m_cert(cert) {
        assert(m_cert);
    }

    std::wstring Name(DWORD type) const {
        DWORD len = CertNameToStrW(m_cert->dwCertEncodingType, &m_cert->pCertInfo->Subject, type, nullptr, 0); // length, including null-termination
        if (!len)
            return L"";

        // print certificate name
        std::wstring buffer(len-1, L'\0');
        len = CertNameToStrW(m_cert->dwCertEncodingType, &m_cert->pCertInfo->Subject, type, buffer.data(), (DWORD)buffer.size()+1);
        assert(len > 0);
        return buffer;
    }

    /** Check if a certificate will expire within the next "X" days. */
    bool WillExpireInDays(int days) const {
        assert(m_cert->pCertInfo);

        // get current time in UTC
        FILETIME currentTime = {};
        GetSystemTimePreciseAsFileTime(&currentTime);

        // move current time "X" days forward
        static constexpr uint64_t SECOND = 10000000L; // 100-nanosecond scale
        (uint64_t&)currentTime += days * 24 * 60 * 60 * SECOND;

        // check if certificate will then have expired
        LONG diff = CompareFileTime(&m_cert->pCertInfo->NotAfter, &currentTime);
        return diff < 0;
    }

    /** CertGetCertificateContextProperty convenience wrapper.
        Expects the query to either succeed or fail with CRYPT_E_NOT_FOUND. */
    std::vector<BYTE> ContextProperty(DWORD prop) const {
        DWORD buffer_len = 0;
        if (!CertGetCertificateContextProperty(m_cert, prop, nullptr, &buffer_len)) {
            DWORD err = GetLastError();
            if (err == CRYPT_E_NOT_FOUND)
                return {};

            abort();
        }
        std::vector<BYTE> buffer(buffer_len, 0);
        if (!CertGetCertificateContextProperty(m_cert, prop, buffer.data(), &buffer_len)) {
            DWORD err = GetLastError();
            err;
            abort();
        }

        return buffer;
    }

    /** Returns SHA-1 thumbprint as hex-encoded string. */
    std::wstring ThumbPrintHex() const {
        std::vector<BYTE> thumbprint = ContextProperty(CERT_HASH_PROP_ID);

        std::wstring result(2*thumbprint.size(), L'\0');
        for (size_t i = 0; i < thumbprint.size(); ++i)
            swprintf(result.data() + 2*i, 2+1, L"%02x", thumbprint[i]);

        return result;
    }

    /** CertGetEnhancedKeyUsage convenience wrapper. Returns empty string if no EKU fields are found. */
    std::vector<std::string> EnhancedKeyUsage(DWORD flags) const {
        DWORD len = 0;
        BOOL ok = CertGetEnhancedKeyUsage(m_cert, flags, nullptr, &len);
        if (!ok || (len == 0))
            return {};

        std::vector<BYTE> eku_buf;
        eku_buf.resize(len, (BYTE)0);
        ok = CertGetEnhancedKeyUsage(m_cert, flags, (CERT_ENHKEY_USAGE*)eku_buf.data(), &len);
        assert(ok);

        auto* eku = (CERT_ENHKEY_USAGE*)eku_buf.data();

        std::vector<std::string> result;
        for (DWORD i = 0; i < eku->cUsageIdentifier; ++i)
            result.push_back(eku->rgpszUsageIdentifier[i]);

        return result;
    }

private:
    const CERT_CONTEXT* m_cert = nullptr; //< weak ptr.
};

class CertStore {
public:
    CertStore(const wchar_t storename[], bool perUser) {
        m_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, perUser ? CERT_SYSTEM_STORE_CURRENT_USER : CERT_SYSTEM_STORE_LOCAL_MACHINE, storename);
        if (m_store == NULL)
            abort();

    }
    ~CertStore() {
        CertCloseStore(m_store, 0);
    }

    /** Cetificate iterator. Returns nullptr at end. */
    const CERT_CONTEXT* Next() {
        m_cert = CertEnumCertificatesInStore(m_store, m_cert);
        return m_cert;
    }

private:
    HCERTSTORE          m_store = nullptr;
    const CERT_CONTEXT* m_cert = nullptr; ///< iterator
};


void CertAccessWin32() {
    CertStore store(L"My", true);

    for (auto it = store.Next(); it; it = store.Next()) {
        Certificate cert(it);
        std::wcout << L"Cert: " << cert.Name(CERT_SIMPLE_NAME_STR) << L'\n';

        if (cert.WillExpireInDays(31)) {
            std::wcout << L"  Cert will expire within a month.\n";
            continue;
        }

        std::wcout << L"  Thumbprint: " << cert.ThumbPrintHex() << L'\n';

        std::vector<std::string> ekus = cert.EnhancedKeyUsage(0);
        for (auto eku : ekus)
            std::cout << "  EKU: " << eku << '\n';

        std::vector<BYTE> prov_buf = cert.ContextProperty(CERT_KEY_PROV_INFO_PROP_ID);
        if (prov_buf.empty())
            continue; // no private key

        CRYPT_KEY_PROV_INFO* provider = (CRYPT_KEY_PROV_INFO*)prov_buf.data();
        std::wcout << L"  Provider: " << provider->pwszProvName << L'\n';
        std::wcout << L"  Container: " << provider->pwszContainerName << L'\n';

        if (provider->dwProvType != 0) {
            std::wcout << L"  Not a CNG type key\n";
            continue;
        }

        CNGKey cng(provider->pwszProvName, provider->pwszContainerName, provider->dwKeySpec);
        cng.Property(NCRYPT_NAME_PROPERTY);
    }
}
