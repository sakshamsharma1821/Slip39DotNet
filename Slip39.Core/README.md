# SLIP-0039 Core Library

A robust and specification-compliant implementation of SLIP-0039 Shamir's Secret Sharing for .NET.

## Overview

This library provides a complete implementation of the SLIP-0039 specification for splitting and combining cryptographic secrets using Shamir's Secret Sharing. It supports both simple single-group and complex multi-group configurations.

## Key Features

- **Full SLIP-0039 Compliance**: Implements the complete specification including all validation rules
- **Multi-Group Support**: Advanced configurations with group thresholds and member thresholds
- **Robust Validation**: Comprehensive input validation and error handling
- **BIP32 Integration**: Generate BIP32 extended private keys from recovered secrets
- **Checksum Validation**: RS1024 checksum verification for data integrity
- **Unicode Support**: Proper passphrase normalization according to SLIP-0039 spec

## Core Components

### Main Classes

- **`Slip39Share`**: Represents a SLIP-0039 share with all metadata
- **`Slip39ShareGeneration`**: Generate shares with single or multi-group configurations
- **`Slip39ShareCombination`**: Combine shares to recover secrets with full validation
- **`Slip39ShareParser`**: Parse shares from mnemonic phrases, hex, or JSON
- **`Slip39Encryption`**: PBKDF2-based encryption/decryption with Feistel network

### Supporting Components

- **`Rs1024Checksum`**: Reed-Solomon checksum calculation and validation
- **`PolynomialInterpolation`**: Shamir's Secret Sharing polynomial operations
- **`GaloisField256`**: Galois Field GF(256) arithmetic
- **`Wordlist`**: SLIP-0039 official wordlist management
- **`Bip32MasterKey`**: BIP32 extended private key generation

## Usage Examples

### Single Group (Simple)

```csharp
// Generate 3 shares, requiring 2 to recover
var groupConfigs = new List<Slip39ShareGeneration.GroupConfig>
{
    new(memberThreshold: 2, memberCount: 3)
};

var shares = Slip39ShareGeneration.GenerateShares(
    groupThreshold: 1,
    groupConfigs: groupConfigs,
    masterSecret: secretBytes,
    passphrase: "mypassphrase",
    iterationExponent: 0,
    isExtendable: false
);

// Recover the secret
var recoveredSecret = Slip39ShareCombination.CombineShares(shares.Take(2).ToList(), "mypassphrase");
```

### Multi-Group (Advanced)

```csharp
// Create a 2-of-3 group configuration:
// - Group 1: 2-of-3 shares (executives)
// - Group 2: 3-of-5 shares (directors)
// - Group 3: 1-of-1 shares (emergency key)
// Any 2 groups can recover the secret

var groupConfigs = new List<Slip39ShareGeneration.GroupConfig>
{
    new(memberThreshold: 2, memberCount: 3), // Executives
    new(memberThreshold: 3, memberCount: 5), // Directors
    new(memberThreshold: 1, memberCount: 1)  // Emergency
};

var shares = Slip39ShareGeneration.GenerateShares(
    groupThreshold: 2, // Need 2 groups
    groupConfigs: groupConfigs,
    masterSecret: secretBytes,
    passphrase: null, // Defaults to "TREZOR"
    iterationExponent: 0,
    isExtendable: false
);
```

### Parse and Inspect Shares

```csharp
// Parse from mnemonic
var share = Slip39ShareParser.ParseFromMnemonic("mild isolate academic acid...");

// Inspect share properties
Console.WriteLine($"Identifier: {share.Identifier}");
Console.WriteLine($"Group {share.GroupIndex}: need {share.ActualMemberThreshold} of {share.ActualGroupCount}");
Console.WriteLine($"Total iterations: {share.TotalIterations:N0}");

// Validate compatibility
if (share1.IsCompatibleWith(share2))
{
    Console.WriteLine("Shares can be combined");
}

// Check logical validity
if (share.IsLogicallyValid())
{
    Console.WriteLine("Share has valid configuration");
}
```

### Generate BIP32 Keys

```csharp
// Recover secret and generate BIP32 master key
var masterSecret = Slip39ShareCombination.CombineShares(shares, passphrase);
var bip32Key = Bip32MasterKey.GenerateMasterKey(masterSecret);
Console.WriteLine($"BIP32 Key: {bip32Key}"); // xprv...
```

## Security Features

### Passphrase Handling
- Automatic Unicode normalization (NFKD)
- Default passphrase "TREZOR" when none specified
- Secure PBKDF2 with configurable iteration counts

### Validation
- Comprehensive share validation before combination
- RS1024 checksum verification
- Group and member threshold validation
- Compatible share detection

### Encryption
- 4-round Feistel network
- PBKDF2-SHA256 with 10,000 × 2^e iterations
- Proper salt generation for non-extendable shares

## Error Handling

The library provides detailed error messages for all failure conditions:

- Invalid mnemonic words or checksums
- Insufficient shares for recovery
- Incompatible share combinations
- Out-of-range field values
- Malformed input data

## Thread Safety

All static methods are thread-safe. Share objects are immutable after construction.

## Performance

- Optimized Galois Field operations
- Efficient polynomial interpolation
- Minimal memory allocations
- Fast checksum validation

## Compliance

This implementation follows the official SLIP-0039 specification:
- Correct bit encoding and endianness
- Standard wordlist usage
- Compliant encryption parameters
- Full support for extendable and non-extendable shares
- Proper padding and checksum handling
