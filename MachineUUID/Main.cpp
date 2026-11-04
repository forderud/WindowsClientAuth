#include <Windows.h>
#include <string>
#include <stdexcept>
#include <vector>


/** From https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable */
struct RawSMBIOSData {
    BYTE  Used20CallingMethod; // observed to be 0
    BYTE  SMBIOSMajorVersion;  // observed to be 3
    BYTE  SMBIOSMinorVersion;  // observed to be 3
    BYTE  DmiRevision;         // observed to be 0
    DWORD Length;
    BYTE  SMBIOSTableData[1 /*Length*/];
};

class SmBiosQuery {
public:
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

    SmBiosQuery() {
        int ret = GetSystemFirmwareTable('RSMB', 0, 0, 0); // returns required buffer size
        if (!ret)
            throw std::runtime_error("GetSystemFirmwareTable get size failed");

        m_buffer.resize(ret);
        ret = GetSystemFirmwareTable('RSMB', 0, m_buffer.data(), (DWORD)m_buffer.size()); // SMBIOS firmware table
        if (!ret)
            throw std::runtime_error("GetSystemFirmwareTable RSMB failed");

        // sanity check
        const auto* Smbios = (RawSMBIOSData*)m_buffer.data();
        if (Smbios->Length != m_buffer.size() - 8)
            throw std::runtime_error("Smbios length error");

        if (Smbios->SMBIOSMajorVersion * 0x100 + Smbios->SMBIOSMinorVersion < 0x0206)
            throw std::runtime_error("SMBIOS older than 2.6 not supported"); // 2.6 was released in 04 Aug 2008
    }

    const RawSMBIOSData* GetData() const {
        return (RawSMBIOSData*)m_buffer.data();
    }

private:
    std::vector<BYTE> m_buffer;
};


static void dmi_system_uuid(const BYTE* p) {
    // print 128bit UUID on little-endian system
    printf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
        p[3], p[2], p[1], p[0], // 32bit Data1
        p[5], p[4], // 16bit Data2
        p[7], p[6], // 16bit Data3
        p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]); // 8 x 8bit Data4[]
}


const char* dmi_string(const SmBiosQuery::Header* dm, BYTE string_number) {
    if (string_number == 0)
        return "Not Specified";

    // pointer to structure payload
    char* ptr = (char*)dm + dm->length;

    // iterate over string until reaching the desired string number
    while (string_number > 1 && *ptr) {
        ptr += strlen(ptr) + 1; // add null termination
        string_number--;
    }

    return ptr;
}


int main (int argc, char* argv[]) {
    SmBiosQuery smbios;
    const RawSMBIOSData* Smbios = smbios.GetData();
    const BYTE* p = Smbios->SMBIOSTableData;

    bool fw_printed = false;
    for (unsigned int i = 0; i < Smbios->Length; i++) {
        const auto* h = (SmBiosQuery::Header*)p;

        if (h->type == SmBiosQuery::PlatformFirmwareInformation && !fw_printed) {
            printf("\nType %02d - [BIOS]\n", h->type);
            printf("\tBIOS Vendor : %s\n", dmi_string(h, p[0x4])); // Vendor offset: 0x4
            printf("\tBIOS Version: %s\n", dmi_string(h, p[0x5])); // FW version offset: 0x5
            printf("\tRelease Date: %s\n", dmi_string(h, p[0x8])); // FW date offset: 0x8

            if (p[0x16] != 0xff && p[0x17] != 0xff)
                printf("\tEC version: %d.%d\n", p[0x16], p[0x17]);
            
            fw_printed = true; // only print first entry
        }
        if (h->type == SmBiosQuery::SystemInformation) {
            printf("\nType %02d - [System Information]\n", h->type);
            printf("\tManufacturer: %s\n", dmi_string(h, p[0x4])); // Manufacturer offset: 0x4
            printf("\tProduct Name: %s\n", dmi_string(h, p[0x5])); // Product name offset: 0x5
            printf("\tVersion: %s\n", dmi_string(h, p[0x6])); // Version offset: 0x6
            printf("\tSerial Number: %s\n", dmi_string(h, p[0x7])); // Serial number offset: 0x7
            printf("\tUUID: "); dmi_system_uuid(p + 0x8); // UUID offset: 0x8
            printf("\tSKU Number: %s\n", dmi_string(h, p[0x19])); // SKU number offset: 0x19
            printf("\tFamily: %s\n", dmi_string(h, p[0x1a])); // Family offset: 0x1a
        }

        // advance to next struct header
        p += h->length; // skip over header
        while (*(p) || *(p+1)) // skip over string-sets
            p++;
        p += 2;
    }

    return 0;
}
