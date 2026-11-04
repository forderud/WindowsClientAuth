#include <Windows.h>
#include <functional>
#include <string>
#include <stdexcept>
#include <vector>

/** Utility class for retrieving SMBIOS parameters. */
class SMBIOSQuery {
    /** From https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable */
    struct RawSMBIOSData {
        BYTE  Used20CallingMethod; // observed to be 0
        BYTE  SMBIOSMajorVersion;  // observed to be 3
        BYTE  SMBIOSMinorVersion;  // observed to be 3
        BYTE  DmiRevision;         // observed to be 0
        DWORD Length;
        BYTE  SMBIOSTableData[1 /*Length*/];
    };

    /* SMBIOD struct type (values 0-127 are reserved) */
    enum Type : BYTE {
        PlatformFirmwareInformation = 0,
        SystemInformation = 1,
    };

    /** From SMBIOS 6.1.2 Structure header format */
    struct Header {
        Type type;
        BYTE length; // lenght (excluding string-sets)
        WORD handle; // unique struct identifier
    };

public:
    SMBIOSQuery() {
        int ret = GetSystemFirmwareTable('RSMB', 0, 0, 0); // returns required buffer size
        if (!ret)
            throw std::runtime_error("GetSystemFirmwareTable get size failed");

        m_buffer.resize(ret);
        ret = GetSystemFirmwareTable('RSMB', 0, m_buffer.data(), (DWORD)m_buffer.size()); // SMBIOS firmware table
        if (!ret)
            throw std::runtime_error("GetSystemFirmwareTable get buffer failed");

        // sanity check
        const auto* Smbios = (RawSMBIOSData*)m_buffer.data();
        if (Smbios->Length != m_buffer.size() - 8)
            throw std::runtime_error("SMBIOS incorrect buffer length");

        // fail early on unsupported versions
        if (Smbios->SMBIOSMajorVersion * 0x100 + Smbios->SMBIOSMinorVersion < 0x0206)
            throw std::runtime_error("SMBIOS older than 2.6 not supported"); // 2.6 was released in 04 Aug 2008
    }

    /** Get the Universally unique identifier (UUID) for this product. */
    std::string GetUUID() const {
        std::string uuid;
        auto getUuid = [&uuid](const Header* header) {
            const auto* ptr = (const BYTE*)header;

            if (header->type == SystemInformation) {
                uuid = GetUUID(ptr + 0x8); // UUID offset: 0x8
            }
        };

        Traverse(getUuid);
        return uuid;
    }

    /** Print a subset of the SMBIOS parameters. */
    void PrintContent() const {
        bool fw_printed = false;
        auto printStruct = [&fw_printed](const Header* header) {
            const auto* ptr = (const BYTE*)header;

            if (header->type == PlatformFirmwareInformation && !fw_printed) {
                printf("\nType %02d - [BIOS]\n", header->type);
                printf("\tBIOS Vendor : %s\n", GetString(header, ptr[0x4])); // Vendor offset: 0x4
                printf("\tBIOS Version: %s\n", GetString(header, ptr[0x5])); // FW version offset: 0x5
                printf("\tRelease Date: %s\n", GetString(header, ptr[0x8])); // FW date offset: 0x8

                if (ptr[0x16] != 0xff && ptr[0x17] != 0xff)
                    printf("\tEC version: %d.%d\n", ptr[0x16], ptr[0x17]);

                fw_printed = true; // only print first entry
            }
            if (header->type == SystemInformation) {
                printf("\nType %02d - [System Information]\n", header->type);
                printf("\tManufacturer: %s\n", GetString(header, ptr[0x4])); // Manufacturer offset: 0x4
                printf("\tProduct Name: %s\n", GetString(header, ptr[0x5])); // Product name offset: 0x5
                printf("\tVersion: %s\n", GetString(header, ptr[0x6])); // Version offset: 0x6
                printf("\tSerial Number: %s\n", GetString(header, ptr[0x7])); // Serial number offset: 0x7
                printf("\tUUID: %s\n", GetUUID(ptr + 0x8).c_str()); // UUID offset: 0x8
                printf("\tSKU Number: %s\n", GetString(header, ptr[0x19])); // SKU number offset: 0x19
                printf("\tFamily: %s\n", GetString(header, ptr[0x1a])); // Family offset: 0x1a
            }
        };

        Traverse(printStruct);
    }

private:
    const RawSMBIOSData* GetData() const {
        return (RawSMBIOSData*)m_buffer.data();
    }

    typedef std::function<void(const Header* header)> StructVisitor;

    void Traverse(StructVisitor visitor) const {
        const RawSMBIOSData* Smbios = GetData();
        const BYTE* ptr = Smbios->SMBIOSTableData;

        bool fw_printed = false;
        while (ptr < Smbios->SMBIOSTableData + Smbios->Length) {
            const auto* h = (Header*)ptr;

            visitor(h);

            // advance to next struct header
            ptr += h->length; // skip over header
            while (*(ptr) || *(ptr + 1)) // advance until reaching two consecutive null characters
                ptr++;
            ptr += 2;
        }
    }

    static std::string GetUUID(const BYTE* p) {
        char buffer[37]{}; // 36 characters + null termination
        snprintf(buffer, sizeof(buffer), "%04x-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            *(uint32_t*)p, // 32bit Data1
            p[5], p[4], // 16bit Data2 (little endian encoded)
            p[7], p[6], // 16bit Data3 (little endian encoded)
            p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]); // 8 x 8bit Data4[]
        return buffer;
    }

    static const char* GetString(const Header* header, BYTE string_number) {
        if (string_number == 0)
            return nullptr; // no string

        // pointer to structure payload
        char* ptr = (char*)header + header->length;

        // iterate over string until reaching the desired string number
        while (string_number > 1 && *ptr) {
            ptr += strlen(ptr) + 1; // add null termination
            string_number--;
        }

        return ptr;
    }

    std::vector<BYTE> m_buffer;
};


int main (int argc, char* argv[]) {
    // query SMBIOS
    SMBIOSQuery smbios;

    // print some of the content
    smbios.PrintContent();
    printf("UUID: %s\n", smbios.GetUUID().c_str());
    return 0;
}
