## TPM identification sample code

All TPM chips contain an [Endorsement Key (EK) that is unique for every TPM and can identify it](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/tpm-key-attestation). The EK can't be changed or removed, except if replacing the TPM chip.

The public-key part of the TPM Endorsement Key (`EKpub`) can thererfore serve as a unique and tamper-proof machine identifier. A more compact secure identifier can be computed by taking the SHA-256 hash of `EKpub`.

PowerShell sample: `(Get-TpmEndorsementKeyInfo -Hash "Sha256").PublicKeyHash` (require admin privileges).

The C++ `TpmIdentifier` project in this folder demonstrates how to compute the SHA-256 hash of `EKpub` without admin privileges. It also demonstrates how to compute the CRC-32 checksum of `EKpub` if a more compact 32bit machine identifier is needed.

### C# sample code
Retrieve `EKpub` from TPM:
```
// Add "Microsoft.Windows.CsWin32" NuGet package
// Add "NativeMethods.txt" to project folder with NCryptOpenStorageProvider, NCryptGetProperty & NCRYPT_PCP_RSA_EKPUB_PROPERTY lines to enable PInvoke calls
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Windows.Win32;
using Windows.Win32.Security.Cryptography;

NCryptFreeObjectSafeHandle handle;
PInvoke.NCryptOpenStorageProvider(out handle, CngProvider.MicrosoftPlatformCryptoProvider.Provider, 0);

var data = new byte[1024];
uint dataLen = 0;
PInvoke.NCryptGetProperty(handle, PInvoke.NCRYPT_PCP_RSA_EKPUB_PROPERTY, data, out dataLen, 0);
Array.Resize(ref data, (int)dataLen);

// Extract RSA modulus and exponent from "data" array
var tmp = GCHandle.Alloc(data, GCHandleType.Pinned);
var header = (BCRYPT_RSAKEY_BLOB)Marshal.PtrToStructure(tmp.AddrOfPinnedObject(), typeof(BCRYPT_RSAKEY_BLOB));
tmp.Free();
var rsa = new RSAParameters();
rsa.Exponent = new byte[header.cbPublicExp];
Array.Copy(data, Marshal.SizeOf(header), rsa.Exponent, 0, header.cbPublicExp);
rsa.Modulus = new byte[header.cbModulus];
Array.Copy(data, Marshal.SizeOf(header) + header.cbPublicExp, rsa.Modulus, 0, header.cbModulus);
var EKpub = RSA.Create(rsa).ExportRSAPublicKey();
```
