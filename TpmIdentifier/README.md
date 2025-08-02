## TPM identification sample code

All TPM chips contain an [Endorsement Key (EK) that is unique for every TPM and can identify it](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/tpm-key-attestation). The EK can't be changed or removed, except if replacing the TPM chip.

The public-key part of the TPM Endorsement Key (`EKpub`) can thererfore serve as a unique and tamper-proof machine identifier. A more compact secure identifier can be computed by taking the SHA-256 hash of `EKpub`.

PowerShell sample: `(Get-TpmEndorsementKeyInfo -Hash "Sha256").PublicKeyHash` (run with admin privileges)

The C++ `TpmIdentifier` project in this folder demonstrates how to compute the SHA-256 hash `EKpub` without admin privileges. It also demonstrates how to compute the CRC-32 checksum of `EKpub` if a more compact machine identifier is needed.
