/* Program to get a unique identifier for the TPM chip on the computer. 
   Computes the SHA-256 hash of the public-key part of the TPM endorsement key (EKpub).
   The EK is unique for every TPM and can identify it. The EK can't be changed or removed (from https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/tpm-key-attestation). */
#include <windows.h>
#include <bcrypt.h> // basic cryptographic primitives
#include <ncrypt.h> // key storage and retrieval
#include <cassert>
#include <fstream>
#include <vector>

#pragma comment(lib, "Ncrypt.lib")
#pragma comment(lib, "Crypt32.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

/** RSA public key BLOB */
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
        Based on the WritePkcs1PublicKey function in https://github.com/dotnet/runtime/blob/main/src/libraries/Common/src/System/Security/Cryptography/RSAKeyFormatHelper.Pkcs1.cs
        Matches the following implementations:
        * PowerShell: (Get-TpmEndorsementKeyInfo -Hash "Sha256").PublicKey
        * .Net: RSA.Create(parameters).ExportRSAPublicKey() with parameters.Exponent and parameters.Modulus set. */
    std::vector<BYTE> PublicKey() const {
        // Encoding reference: https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-der-encoding-of-asn-1-types
        std::vector<BYTE> data;
#if 1
        auto modulus = Modulus();
        uint16_t modLen = (uint16_t)modulus.size(); // typ. 256bytes
        if (modulus[0] & 0x80)
            modLen += 1; // need to add leading byte to signal positive value

        auto exponent = Exponent();
        uint8_t expLen = (uint8_t)exponent.size(); // typ. 3bytes
        if (exponent[0] & 0x80)
            expLen += 1; // need to add leading byte to signal positive value

        uint16_t payloadLen = (4 + modLen) + (2 + expLen); // typ. 266bytes

        data.push_back(0x30); // SEQUENCE
        data.push_back(0x82); // 2 bytes length prefix (MSB set)
        data.push_back(payloadLen >> 8); // payload length (big-endian)
        data.push_back(payloadLen & 0xFF);

        {
            // Modulus parameter
            data.push_back(0x02); // INTEGER value
            data.push_back(0x82); // 2 bytes length prefix (MSB set)
            data.push_back(modLen >> 8); // modulus length (big-endian)
            data.push_back(modLen & 0xFF);
            if (modulus[0] & 0x80)
                data.push_back(0x00); // add leading 0x00 to indicate positive value
            data.insert(data.end(), modulus.begin(), modulus.end());
        }
        {
            // Exponent parameter
            data.push_back(0x02); // INTEGER value
            data.push_back(expLen); // exponent length
            if (exponent[0] & 0x80)
                data.push_back(0x00); // add leading 0x00 to indicate positive value
            data.insert(data.end(), exponent.begin(), exponent.end());
        }
#else
        // work-in-progress alternative impl.
        NCRYPT_PROV_HANDLE provHandle = 0;
        NCryptOpenStorageProvider(&provHandle, MS_KEY_STORAGE_PROVIDER, 0);

        // step 1: Import BCRYPT_RSAKEY_BLOB-encoded key 
        NCRYPT_KEY_HANDLE nkey = 0;
        SECURITY_STATUS status = NCryptImportKey(provHandle, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, &nkey, data.data(), (DWORD)data.size(), 0);

        BCRYPT_ALG_HANDLE algHandle = 0;
        std::string keyObj = ""; // optional
        NTSTATUS status2 = BCryptImportKey(algHandle, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, (UCHAR*)keyObj.c_str(), (DWORD)keyObj.length(), data.data(), (DWORD)data.size(), 0);

        // step 2: Export ASN.1 DER encoding
        // TODO: Implement

        NCryptFreeObject(provHandle);
#endif
        return data;
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
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        abort();

    // get scratch buffer size
    DWORD scratchBufLen = 0, scratchBufLenSize = 0;
    if (!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (UCHAR*)&scratchBufLen, sizeof(scratchBufLen), &scratchBufLenSize, 0)))
        abort();
    assert(scratchBufLenSize == sizeof(scratchBufLen));

    // create a hash object
    std::vector<BYTE> scratchBuf(scratchBufLen, 0);
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (!NT_SUCCESS(status = BCryptCreateHash(hAlg, &hHash, scratchBuf.data(), (ULONG)scratchBuf.size(), NULL, 0, 0)))
        abort();

    // compute hash of data
    if (!NT_SUCCESS(status = BCryptHashData(hHash, (UCHAR*)data.data(), (ULONG)data.size(), 0)))
        abort();

    // get hash value
    if (!NT_SUCCESS(status = BCryptFinishHash(hHash, hash.data(), (ULONG)hash.size(), 0)))
        abort();

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return hash;
}

/** Compute 32bit cyclic redundancy checksum (CRC-32). */
static uint32_t Crc32Checksum(const std::vector<BYTE>& data) {
#if 1
    // low-level implementation based on https://en.wikipedia.org/wiki/Computation_of_cyclic_redundancy_checks#CRC-32_example
    uint32_t CRCTable[256] = {};
    {
        // table initialization
        uint32_t crc32 = 1;
        // CRCTable[0] = 0 already.
        for (unsigned int i = 128; i; i >>= 1) {
            crc32 = (crc32 >> 1) ^ (crc32 & 1 ? 0xedb88320 : 0);
            for (unsigned int j = 0; j < 256; j += 2 * i)
                CRCTable[i + j] = crc32 ^ CRCTable[j];
        }
    }

    uint32_t crc32 = 0xFFFFFFFFu;
    for (size_t i = 0; i < data.size(); i++) {
        crc32 ^= data[i];
        crc32 = (crc32 >> 8) ^ CRCTable[crc32 & 0xff];
    }

    // Finalize the CRC-32 value by inverting all the bits
    crc32 ^= 0xFFFFFFFFu;
    return crc32;
#else
    // call undocumented RtlComputeCrc32 function in Ntdll.dll
    // intended as reference to verify correctness of the implementation above
    typedef DWORD (WINAPI* RtlComputeCrc32Fn)(DWORD initial, const BYTE* buffer, UINT buflen);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto RtlComputeCrc32 = (RtlComputeCrc32Fn)GetProcAddress(ntdll, "RtlComputeCrc32");

    return RtlComputeCrc32(0, data.data(), (UINT)data.size());
#endif
}


int main() {
    RsaPublicBlob rsaBlob;
    {
        // connect to TPM chip that is exposed through the "Microsoft Platform Crypto Provider"
        NCRYPT_PROV_HANDLE hProv = NULL;
        SECURITY_STATUS ret = NCryptOpenStorageProvider(&hProv, MS_PLATFORM_CRYPTO_PROVIDER, 0);
        if (ret != ERROR_SUCCESS) {
            printf("ERROR: Unable to connect to TPM chip.\n");
            abort();
        }

        // Retrieve TPM Endorsement Key public key (EKpub) as RSA public key BLOB.
        // This key is unique for every TPM and can identify it. It cannot be changed, except if replacing the TPM chip.
        // DOC: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
        rsaBlob.buffer.resize(1024, 0);
        DWORD ekPub_len = 0;
        ret = NCryptGetProperty(hProv, NCRYPT_PCP_RSA_EKPUB_PROPERTY, rsaBlob.buffer.data(), (DWORD)rsaBlob.buffer.size(), &ekPub_len, 0); // "PCP_RSA_EKPUB"
        if (ret != ERROR_SUCCESS) {
            printf("ERROR: Unable to retrieve TPM Endorsement Key public key (EKpub).\n");
            abort();
        }
        rsaBlob.buffer.resize(ekPub_len);

        NCryptFreeObject(hProv);
    }

#if 0
    rsaBlob.PrintHeader();
    rsaBlob.SaveToFile("TPM_EKpub.bin");
#endif

    // compute hash that matches the PowerShell (Get-TpmEndorsementKeyInfo -Hash "Sha256").PublicKeyHash command
    printf("Retrieving Endorsement Key public key (EKpub) from the Trusted Platform Module (TPM).\n");
    printf("This key is unique for every TPM and can identify it. It cannot be changed, except if replacing the TPM.\n");
    printf("\n");
    std::vector<BYTE> EKpub = rsaBlob.PublicKey();

    std::vector<BYTE> hash = Sha256Hash(EKpub);
    printf("TPM EKpub SHA-256 hash: ");
    for (BYTE elm : hash)
        printf("%02x", elm);
    printf(" (secure identifier)\n");

    uint32_t crc32 = Crc32Checksum(EKpub);
    printf("TPM EKpub CRC-32 checksum: %x (insecure identifier)\n", crc32);
}
