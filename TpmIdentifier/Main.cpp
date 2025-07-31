#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <cassert>
#include <fstream>
#include <vector>

#pragma comment(lib, "Ncrypt.lib")
#pragma comment(lib, "Crypt32.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

struct RsaPublicBlob {
    std::vector<BYTE> buffer; // BCRYPT_RSAKEY_BLOB public key buffer

    BCRYPT_RSAKEY_BLOB* Header() const {
        auto* header = (BCRYPT_RSAKEY_BLOB*)buffer.data();
        assert(header->Magic == BCRYPT_RSAPUBLIC_MAGIC); // 0x31415352  // RSA1
        return header;
    }

    /** Return RSA exponent in big-endian format */
    std::vector<BYTE> Exponent() const {
        BCRYPT_RSAKEY_BLOB* header = Header();

        const BYTE* ptr = buffer.data() + sizeof(BCRYPT_RSAKEY_BLOB);
        std::vector<BYTE> exponent(header->cbPublicExp, 0); // big-endian
        memcpy(exponent.data(), ptr, header->cbPublicExp);
        return exponent;
    }

    /** Return RSA modulus in big-endian format */
    std::vector<BYTE> Modulus() const {
        BCRYPT_RSAKEY_BLOB* header = Header();

        const BYTE* ptr = buffer.data() + sizeof(BCRYPT_RSAKEY_BLOB) + header->cbPublicExp;
        std::vector<BYTE> modulus(header->cbModulus, 0); // big-endian
        memcpy(modulus.data(), ptr, header->cbModulus);
        ptr += header->cbModulus;
        assert(ptr == buffer.data() + buffer.size()); // reached end of EKpub buffer
        return modulus;
    }

    /** Compute ASN.1 DER encoding of the public key.
        Matches the following implementations:
        * PowerShell: (Get-TpmEndorsementKeyInfo -Hash "Sha256").PublicKeyHash
        * .Net: SHA256.HashData(RSA.Create(parameters).ExportRSAPublicKey()) with parameters.Exponent and parameters.Modulus set. */
    std::vector<BYTE> PublicKey() const {
#if 0
        // TODO: Hash doesn't match (Get-TpmEndorsementKeyInfo -Hash "Sha256").PublicKeyHash
        std::vector<BYTE> hash(32, 0);
        DWORD hash_len = (DWORD)hash.size();

        //BOOL ok = CryptHashCertificate(NULL, CALG_SHA_256, 0, buffer.data(), (DWORD)buffer.size(), hash.data(), &hash_len);
        //assert(ok);

        CERT_PUBLIC_KEY_INFO info{};
        info.Algorithm.pszObjId = (char*)szOID_RSA;
        info.Algorithm.Parameters = { 0, nullptr };
        info.PublicKey = { (DWORD)buffer.size(), (BYTE*)buffer.data(), 0 };

        BOOL ok = CryptHashPublicKeyInfo(NULL, CALG_SHA_256, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &info, hash.data(), &hash_len);
        assert(ok);
        assert(hash_len == hash.size());
        return hash;
#else
        // ASN DER export of Modulus & Exponent parameters (see https://github.com/dotnet/runtime/blob/main/src/libraries/Common/src/System/Security/Cryptography/RSAKeyFormatHelper.Pkcs1.cs)
        // Encoding reference: https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-der-encoding-of-asn-1-types
        std::vector<BYTE> data; // data to be hashed
        
        data.push_back(0x30); // sequence
        data.push_back(0x82); // 2 bytes length (MSB set)
        data.push_back(0x01); // 266bytes
        data.push_back(0x0A); // 

        data.push_back(0x02); // integer
        data.push_back(0x82); // 2 bytes length (MSB set)
        auto modulus = Modulus();
        uint16_t modLen = (uint16_t)modulus.size() + 1; // typ. 257bytes
        data.push_back(((BYTE*)&modLen)[1]);
        data.push_back(((BYTE*)&modLen)[0]);
        data.push_back(0x00); // leading byte
        data.insert(data.end(), modulus.begin(), modulus.end());

        data.push_back(0x02); // integer
        auto exponent = Exponent();
        data.push_back((BYTE)exponent.size()); // typ. 3 bytes
        data.insert(data.end(), exponent.begin(), exponent.end());

        return data;
#endif
    }

    void PrintHeader() const {
        BCRYPT_RSAKEY_BLOB* header = Header();

        printf("Algorithm: ");
        for (size_t i = 0; i < sizeof(header->Magic); i++) {
            BYTE elm = ((BYTE*)&header->Magic)[i];
            printf("%c", elm);
        }
        printf("\n");
        printf("Bit length: %u\n", header->BitLength);
        printf("Exponent length: %u\n", header->cbPublicExp);
        printf("Modulus length: %u\n", header->cbModulus);
        printf("Prime1 length: %u\n", header->cbPrime1);
        printf("Prime2 length: %u\n", header->cbPrime2);
    }

    void SaveToFile(const char* filename) const {
        std::ofstream file(filename, std::ofstream::out | std::ofstream::binary);
        file.write((char*)&buffer, buffer.size());
    }
};

/** Compute SHA-256 hash of the input data. */
static std::vector<BYTE> Sha256Hash(const std::vector<BYTE>& data) {
    std::vector<BYTE> hash(32, 0); // SHA-256 output is always 32bytes

    // open hash algorithm provider
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        abort();
    }

    // get scratch buffer size
    DWORD cbData = 0, cbHashObject = 0;
    if (!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        abort();
    }

    // create a hash object
    std::vector<BYTE> scratchBuf(cbHashObject, 0);
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (!NT_SUCCESS(status = BCryptCreateHash(hAlg, &hHash, scratchBuf.data(), cbHashObject, NULL, 0, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
        abort();
    }

    // compute hash of data
    if (!NT_SUCCESS(status = BCryptHashData(hHash, (UCHAR*)data.data(), (ULONG)data.size(), 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);
        abort();
    }

    // get hash value
    if (!NT_SUCCESS(status = BCryptFinishHash(hHash, hash.data(), (ULONG)hash.size(), 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
        abort();
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return hash;
}


int main() {
    // retrieve TPM Endorsement Key public key (EKpub) as RSA public key BLOB
    // DOC: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
    RsaPublicBlob rsaBlob;
    {
        // connect to TPM chip that is exposed through the "Microsoft Platform Crypto Provider"
        NCRYPT_PROV_HANDLE hProv = NULL;
        HRESULT hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(&hProv, MS_PLATFORM_CRYPTO_PROVIDER, 0));
        if (FAILED(hr))
            abort();

        rsaBlob.buffer.resize(1024, 0);
        DWORD ekPub_len = 0;
        hr = HRESULT_FROM_WIN32(NCryptGetProperty(hProv, NCRYPT_PCP_RSA_EKPUB_PROPERTY, rsaBlob.buffer.data(), (DWORD)rsaBlob.buffer.size(), &ekPub_len, 0)); // "PCP_RSA_EKPUB"
        if (FAILED(hr))
            abort();
        rsaBlob.buffer.resize(ekPub_len);

        NCryptFreeObject(hProv);
    }

#if 0
    rsaBlob.PrintHeader();
    rsaBlob.SaveToFile("TPM_EKpub.bin");
#endif

    // compute hash that matches the PowerShell (Get-TpmEndorsementKeyInfo -Hash "Sha256").PublicKeyHash command
    std::vector<BYTE> hash = Sha256Hash(rsaBlob.PublicKey());
    printf("TPM EKpub public key SHA-256 hash:\n");
    for (BYTE elm : hash)
        printf("%02x", elm);
    printf("\n");
}
