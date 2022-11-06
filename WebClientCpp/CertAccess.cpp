#include "CertAccess.hpp"
#include <iostream>



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
        std::wcout << L"  CNG key access succeeded\n";
    }
}
