# SLIP-0039 .NET Implementation

[![.NET](https://img.shields.io/badge/.NET-9.0-blue.svg)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

A complete .NET implementation of [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) Shamir's Secret Sharing for mnemonic codes, providing both a core library and a command-line interface.

## Features

- ✅ **Complete SLIP-0039 Implementation** - Full compliance with the specification
- ✅ **Shamir's Secret Sharing** - Split secrets into multiple shares with configurable thresholds
- ✅ **Multi-Group Support** - Advanced group-based sharing with flexible recovery strategies
- ✅ **BIP32 Extended Key Support** - Split and recover BIP32 extended private keys (xprv)
- ✅ **BIP32 Master Key Generation** - Generate HD wallet master keys from recovered secrets
- ✅ **Passphrase Support** - Optional passphrase protection for enhanced security
- ✅ **Command Line Interface** - Comprehensive CLI for all operations
- ✅ **Cross-Platform** - Runs on Windows, Linux, and macOS
- ✅ **Comprehensive Testing** - Extensive test suite with official test vectors
- ✅ **Memory Safety** - Secure handling of sensitive cryptographic material

## Quick Start

### Installation

#### Using .NET CLI
```bash
git clone https://github.com/yourusername/Slip39DotNet.git
cd Slip39DotNet
dotnet build
```

#### Using the CLI Tool
```bash
# Split a 256-bit secret into shares
dotnet run --project Slip39.Console split --secret "a1b2c3d4e5f67890abcdef1234567890fedcba0987654321a1b2c3d4e5f67890" --threshold 2 --shares 3

# Combine shares to recover the secret
dotnet run --project Slip39.Console combine "mnemonic1" "mnemonic2"

# Split a BIP32 extended private key into shares
dotnet run --project Slip39.Console split-xpriv --xpriv "xprv9s21ZrQH143K..." --threshold 2 --shares 3

# Generate random secret and split into shares
dotnet run --project Slip39.Console generate --bits 256 --threshold 2 --shares 3
```

### Library Usage

```csharp
using Slip39.Core;

// Split a 128-bit secret into shares
var secret = Convert.FromHexString("a1b2c3d4e5f67890abcdef1234567890");
var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(2, 3) };
var shares = Slip39ShareGeneration.GenerateShares(
    groupThreshold: 1,
    groupConfigs: groupConfigs,
    masterSecret: secret,
    passphrase: "optional_passphrase"
);

// Convert shares to mnemonics
var mnemonics = shares.Select(share => share.ToMnemonic()).ToArray();

// Later, combine shares to recover the secret
var recoveredSecret = Slip39ShareCombination.CombineShares(shares.Take(2).ToList(), "optional_passphrase");
Console.WriteLine($"Recovered: {Convert.ToHexString(recoveredSecret)}");

// Generate BIP32 master key from recovered secret
var masterKey = Bip32MasterKey.GenerateMasterKey(recoveredSecret, "optional_passphrase");
Console.WriteLine($"Master Key: {masterKey}");
```

### Multi-Group Shares

SLIP-0039 supports multi-group shares, allowing you to create different groups with separate recovery thresholds. This provides more flexible recovery strategies.

```csharp
using Slip39.Core;

// Define a 256-bit secret
var secret = Convert.FromHexString("a1b2c3d4e5f67890abcdef1234567890fedcba0987654321a1b2c3d4e5f67890");

// Define groups with their thresholds and share counts
var groupConfigs = new List<Slip39ShareGeneration.GroupConfig>
{
    new(2, 3), // Group 1: 2-of-3 shares needed
    new(1, 2)  // Group 2: 1-of-2 shares needed  
};

// Generate multi-group shares (need 1 group to recover)
var shares = Slip39ShareGeneration.GenerateShares(
    groupThreshold: 1,
    groupConfigs: groupConfigs,
    masterSecret: secret,
    passphrase: "optional_passphrase"
);

// Convert shares to mnemonics
var mnemonics = shares.Select(share => share.ToMnemonic()).ToArray();

// To recover the secret, you need to meet the threshold for at least one group
// For example, provide 2 shares from Group 1 OR 1 share from Group 2
var group1Shares = shares.Where(s => s.GroupIndex == 0).Take(2).ToList();
var recoveredSecret = Slip39ShareCombination.CombineShares(group1Shares, "optional_passphrase");
Console.WriteLine($"Recovered: {Convert.ToHexString(recoveredSecret)}");
```

### BIP32 Extended Private Key Support

SLIP39DotNet provides native support for backing up BIP32 extended private keys (xprv) using SLIP-0039 shares. This allows you to securely backup and recover HD wallet master keys.

```csharp
using Slip39.Core;

// Your BIP32 extended private key (from hardware wallet, etc.)
var originalXpriv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

// Decode and extract the private key and chain code (64 bytes total)
var extendedKeyData = Base58Check.Decode(originalXpriv);
var privateKey = new byte[32];
var chainCode = new byte[32];
Array.Copy(extendedKeyData, 46, privateKey, 0, 32); // Private key at offset 46
Array.Copy(extendedKeyData, 13, chainCode, 0, 32);  // Chain code at offset 13

// Combine into 64-byte master secret
var masterSecret = new byte[64];
Array.Copy(privateKey, 0, masterSecret, 0, 32);
Array.Copy(chainCode, 0, masterSecret, 32, 32);

// Generate SLIP-0039 shares from the BIP32 key
var groupConfigs = new List<Slip39ShareGeneration.GroupConfig> { new(2, 3) };
var shares = Slip39ShareGeneration.GenerateShares(
    groupThreshold: 1,
    groupConfigs: groupConfigs,
    masterSecret: masterSecret,
    passphrase: "TREZOR", // Standard passphrase
    iterationExponent: 0,
    isExtendable: false);

// Later, recover the original xprv from shares
var recoveredSecret = Slip39ShareCombination.CombineShares(shares.Take(2).ToList(), "TREZOR");

// Reconstruct the BIP32 extended private key
// ... (BIP32 reconstruction logic)
var reconstructedXpriv = ReconstructBip32ExtendedKey(recoveredSecret);
Console.WriteLine($"Recovered xprv: {reconstructedXpriv}");
```

**Key Features:**
- **Full xprv Recovery**: Exactly reconstructs the original BIP32 extended private key
- **64-byte Secrets**: Handles the full private key (32 bytes) + chain code (32 bytes)
- **Long Mnemonics**: Generates 59-word mnemonics for 64-byte secrets
- **CLI Integration**: Use `split-xpriv` and `combine --bip32` commands

## Projects

### Slip39.Core
The core library implementing SLIP-0039 specification:
- **Slip39ShareGeneration** - Create mnemonic shares from secrets
- **Slip39ShareCombination** - Recover secrets from shares  
- **Slip39ShareParser** - Parse and validate mnemonic strings
- **Slip39Encryption** - SLIP-0039 encryption/decryption with PBKDF2 and Feistel network
- **Bip32MasterKey** - Generate BIP32 extended private keys
- **Base58Check** - Base58Check encoding/decoding for BIP32 keys
- **Cryptographic primitives** - GF(256) operations, polynomial interpolation, RS1024 checksums
- **Multi-group support** - Advanced group-based sharing configurations

### Slip39.Console  
Command-line interface providing:
- **split** - Split secrets into mnemonic shares
- **split-xpriv** - Split BIP32 extended private keys into shares
- **combine** - Combine shares to recover secrets
- **combine --bip32** - Recover and reconstruct BIP32 extended private keys
- **info** - Display detailed share information
- **validate** - Validate share checksums
- **generate** - Generate random secrets and split into shares
- **Multi-format output** - Text, JSON, and hex output formats

## CLI Commands

### Basic Secret Sharing

```bash
# Split a 128-bit secret into shares (single group)
dotnet run --project Slip39.Console split --secret "a1b2c3d4e5f67890abcdef1234567890" --threshold 2 --shares 3

# Split a 256-bit secret into multi-group shares
# Create 2 groups: Group 1 (3-of-5) and Group 2 (2-of-3) - need 1 group to recover
dotnet run --project Slip39.Console split --secret "a1b2c3d4e5f67890abcdef1234567890fedcba0987654321a1b2c3d4e5f67890" --group-threshold 1 --groups "3-of-5,2-of-3"

# Multi-group requiring 2 out of 3 groups to recover
dotnet run --project Slip39.Console split --secret "a1b2c3d4e5f67890abcdef1234567890fedcba0987654321a1b2c3d4e5f67890" --group-threshold 2 --groups "2-of-3,3-of-5,1-of-1" --passphrase "mypassword"

# Combine shares to recover secret
dotnet run --project Slip39.Console combine "share1" "share2"

# Combine shares and show BIP32 master key
dotnet run --project Slip39.Console combine --bip32 "share1" "share2"
```

### BIP32 Extended Private Key Support

```bash
# Split a BIP32 extended private key (xprv) into SLIP-0039 shares
dotnet run --project Slip39.Console split-xpriv --xpriv "xprv9s21ZrQH143K..." --threshold 2 --shares 3

# Split with custom passphrase and multi-group configuration
dotnet run --project Slip39.Console split-xpriv --xpriv "xprv9s21ZrQH143K..." --group-threshold 2 --groups "2-of-3,3-of-5" --passphrase "mypassword"

# Combine shares to recover the original BIP32 extended private key
dotnet run --project Slip39.Console combine --bip32 "share1" "share2"
```

### Share Management

```bash
# Get detailed information about a share
dotnet run --project Slip39.Console info "share_mnemonic"

# Validate share checksums
dotnet run --project Slip39.Console validate "share1" "share2" "share3"

# Generate random secret and split into shares
dotnet run --project Slip39.Console generate --bits 256 --threshold 2 --shares 3

# Generate with BIP32 master key output
dotnet run --project Slip39.Console generate --bits 256 --threshold 2 --shares 3 --bip32 --show-secret
```

For detailed CLI usage, see [Slip39.Console/README.md](Slip39.Console/README.md).

## Security Considerations

- **Cryptographic Compliance**: Implements SLIP-0039 specification exactly as defined
- **Secure Memory**: Sensitive data is handled securely and cleared when possible
- **Passphrase Protection**: Optional passphrase adds an additional layer of security
- **Threshold Security**: Requires minimum number of shares to recover secrets
- **Checksum Validation**: RS1024 checksums prevent corruption and detect errors

⚠️ **Important**: Keep your mnemonic shares secure and backed up. Loss of shares below the threshold means permanent loss of your secret.

## Testing

The project includes comprehensive tests covering:
- SLIP-0039 reference test vectors
- BIP32 master key derivation
- Cryptographic primitives (GF256, polynomial interpolation)
- Error handling and edge cases
- CLI functionality

```bash
# Run all tests
dotnet test

# Run with coverage
dotnet test --collect:"XPlat Code Coverage"
```

## Requirements

- .NET 9.0 or later
- Supported platforms: Windows, Linux, macOS

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Specification

This implementation follows the [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) specification published by SatoshiLabs.

## Acknowledgments

- SatoshiLabs for the SLIP-0039 specification
- The Bitcoin community for BIP32 specification
- Adi Shamir for Shamir's Secret Sharing algorithm

## AI Development Disclaimer

🤖 **This entire repository was completely vibe-coded using Warp AI Terminal Agent Mode.** Not a single line of code, comment, documentation, or ancillary file was edited manually. The entire SLIP-0039 .NET implementation, CLI application, tests, documentation, and project infrastructure were generated through AI-assisted development in the terminal.

## Disclaimer

This software is provided as-is. While it implements the SLIP-0039 specification and passes all test vectors, users should thoroughly test and audit the code for their specific use cases. The authors are not responsible for any loss of funds or data.
