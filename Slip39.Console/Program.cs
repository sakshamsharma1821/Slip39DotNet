using Slip39.Core;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SystemConsole = System.Console;

namespace Slip39.Console;

class Program
{
    static void Main(string[] args)
    {
        // If no arguments provided, show help
        if (args.Length == 0)
        {
            ShowHelp();
            return;
        }

        string command = args[0].ToLower();

        try
        {
            switch (command)
            {
                case "split":
                    HandleSplitCommand(args[1..]);
                    break;
                case "combine":
                    HandleCombineCommand(args[1..]);
                    break;
                case "info":
                    HandleInfoCommand(args[1..]);
                    break;
                case "validate":
                    HandleValidateCommand(args[1..]);
                    break;
                case "generate":
                    HandleGenerateCommand(args[1..]);
                    break;
                case "split-xpriv":
                    HandleSplitXprivCommand(args[1..]);
                    break;
                case "help":
                    ShowHelp();
                    break;
                default:
                    SystemConsole.WriteLine($"Unknown command: {command}");
                    SystemConsole.WriteLine("Use 'help' to see available commands.");
                    Environment.Exit(1);
                    break;
            }
        }
        catch (Exception ex)
        {
            SystemConsole.WriteLine($"Error: {ex.Message}");
            Environment.Exit(1);
        }
    }

    static void ShowHelp()
    {
        SystemConsole.WriteLine("SLIP-0039 Shamir's Secret Sharing Tool");
        SystemConsole.WriteLine("=====================================\n");
        
        SystemConsole.WriteLine("Available Commands:");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("  split      - Split a secret into SLIP-0039 shares");
        SystemConsole.WriteLine("  split-xpriv- Split a BIP32 extended private key into SLIP-0039 shares");
        SystemConsole.WriteLine("  combine    - Combine SLIP-0039 shares to recover secret");
        SystemConsole.WriteLine("  info       - Display detailed information about a share");
        SystemConsole.WriteLine("  validate   - Validate SLIP-0039 share checksums");
        SystemConsole.WriteLine("  generate   - Generate a random secret and split it");
        SystemConsole.WriteLine("  help       - Show this help message");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("Examples:");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("  # Split a hex secret into 3 shares, requiring 2 to recover:");
        SystemConsole.WriteLine("  slip39 split --secret 458d0765afec7bb0fb45a50a84d5bf74d75a2b1e69fd79015ce2bb23a9ce9ef3 --threshold 2 --shares 3");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("  # Combine shares to recover the original secret:");
        SystemConsole.WriteLine("  slip39 combine --shares \"share1\" \"share2\"");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("  # Show detailed information about a share:");
        SystemConsole.WriteLine("  slip39 info \"mild isolate academic acid apart...\"");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("  # Validate share checksums:");
        SystemConsole.WriteLine("  slip39 validate \"share1\" \"share2\" \"share3\"");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("  # Generate and split a new 256-bit secret:");
        SystemConsole.WriteLine("  slip39 generate --bits 256 --threshold 2 --shares 3");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("  # Split an existing BIP32 extended private key:");
        SystemConsole.WriteLine("  slip39 split-xpriv --xpriv xprv9s21ZrQH... --threshold 2 --shares 3");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("Use 'slip39 [command] --help' for detailed command options.");
    }

    static void HandleSplitCommand(string[] args)
    {
        if (args.Length == 0 || args.Contains("--help"))
        {
            ShowSplitHelp();
            return;
        }

        string? secretHex = null;
        int threshold = 2;
        int shares = 3;
        int groupThreshold = 1;
        var groupConfigs = new List<string>();
        string? passphrase = null;
        byte iterationExponent = 0;
        bool extendable = false;
        string outputFormat = "text";

        // Parse arguments
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--secret":
                    secretHex = GetNextArgument(args, ref i, "--secret");
                    break;
                case "--threshold":
                    threshold = ParseIntArgument(args, ref i, "--threshold");
                    break;
                case "--shares":
                    shares = ParseIntArgument(args, ref i, "--shares");
                    break;
                case "--group-threshold":
                    groupThreshold = ParseIntArgument(args, ref i, "--group-threshold");
                    break;
                case "--groups":
                    groupConfigs.Add(GetNextArgument(args, ref i, "--groups"));
                    break;
                case "--passphrase":
                    passphrase = GetNextArgument(args, ref i, "--passphrase");
                    break;
                case "--iterations":
                    iterationExponent = ParseByteArgument(args, ref i, "--iterations");
                    break;
                case "--extendable":
                    extendable = true;
                    break;
                case "--format":
                    outputFormat = GetNextArgument(args, ref i, "--format");
                    break;
            }
        }

        if (string.IsNullOrEmpty(secretHex))
        {
            SystemConsole.WriteLine("Error: --secret is required");
            return;
        }

        try
        {
            byte[] secret = Convert.FromHexString(secretHex);
            
            List<Slip39ShareGeneration.GroupConfig> parsedGroupConfigs;
            
            // If groups are specified, use multi-group configuration
            if (groupConfigs.Count > 0)
            {
                parsedGroupConfigs = ParseGroupConfigurations(groupConfigs);
                
                // Validate group threshold
                if (groupThreshold > parsedGroupConfigs.Count)
                {
                    SystemConsole.WriteLine($"Error: Group threshold ({groupThreshold}) cannot exceed number of groups ({parsedGroupConfigs.Count})");
                    return;
                }
            }
            else
            {
                // Single group configuration (backward compatibility)
                parsedGroupConfigs = new List<Slip39ShareGeneration.GroupConfig>
                {
                    new(threshold, shares)
                };
                groupThreshold = 1;
            }

            var generatedShares = Slip39ShareGeneration.GenerateShares(
                groupThreshold: groupThreshold,
                groupConfigs: parsedGroupConfigs,
                masterSecret: secret,
                passphrase: passphrase,
                iterationExponent: iterationExponent,
                isExtendable: extendable
            );

            // Display configuration summary
            SystemConsole.WriteLine($"Successfully generated {generatedShares.Count} shares:");
            
            if (parsedGroupConfigs.Count == 1)
            {
                SystemConsole.WriteLine($"Single Group: {threshold} of {shares} shares required to recover");
            }
            else
            {
                SystemConsole.WriteLine($"Multi-Group Configuration: {groupThreshold} groups required out of {parsedGroupConfigs.Count} total groups");
                for (int i = 0; i < parsedGroupConfigs.Count; i++)
                {
                    var config = parsedGroupConfigs[i];
                    SystemConsole.WriteLine($"  Group {i + 1}: {config.MemberThreshold} of {config.MemberCount} shares");
                }
            }
            
            SystemConsole.WriteLine($"Passphrase: {FormatPassphraseDisplay(passphrase)}");
            SystemConsole.WriteLine();

            DisplayGeneratedShares(generatedShares, outputFormat);
        }
        catch (Exception ex)
        {
            SystemConsole.WriteLine($"Error splitting secret: {ex.Message}");
        }
    }
    
    static List<Slip39ShareGeneration.GroupConfig> ParseGroupConfigurations(List<string> groupConfigs)
    {
        var configs = new List<Slip39ShareGeneration.GroupConfig>();
        
        foreach (var configStr in groupConfigs)
        {
            // Parse individual group configurations separated by commas
            var groups = configStr.Split(',', StringSplitOptions.RemoveEmptyEntries);
            
            foreach (var group in groups)
            {
                // Parse format like "2-of-3" or "2/3"
                var parts = group.Trim().Split(new[] { "-of-", "/", ":", " of " }, StringSplitOptions.RemoveEmptyEntries);
                
                if (parts.Length != 2)
                {
                    throw new ArgumentException($"Invalid group configuration format: '{group}'. Expected format: 'threshold-of-total' (e.g., '2-of-3')");
                }
                
                if (!int.TryParse(parts[0].Trim(), out int memberThreshold) || !int.TryParse(parts[1].Trim(), out int memberCount))
                {
                    throw new ArgumentException($"Invalid numbers in group configuration: '{group}'");
                }
                
                if (memberThreshold <= 0 || memberCount <= 0 || memberThreshold > memberCount)
                {
                    throw new ArgumentException($"Invalid group configuration: '{group}'. Threshold must be positive and not exceed total count.");
                }
                
                configs.Add(new Slip39ShareGeneration.GroupConfig(memberThreshold, memberCount));
            }
        }
        
        if (configs.Count == 0)
        {
            throw new ArgumentException("No valid group configurations found");
        }
        
        return configs;
    }

    static void ShowSplitHelp()
    {
        SystemConsole.WriteLine("Split Command - Split a secret into SLIP-0039 shares");
        SystemConsole.WriteLine("==================================================\n");
        
        SystemConsole.WriteLine("Usage:");
        SystemConsole.WriteLine("  slip39 split --secret <hex> [options]\n");
        
        SystemConsole.WriteLine("Required Arguments:");
        SystemConsole.WriteLine("  --secret <hex>     Hexadecimal secret to split (32 or 64 hex chars for 128/256-bit)\n");
        
        SystemConsole.WriteLine("Single Group Mode (Simple):");
        SystemConsole.WriteLine("  --threshold <n>    Number of shares needed to recover (default: 2)");
        SystemConsole.WriteLine("  --shares <n>       Total number of shares to generate (default: 3)\n");
        
        SystemConsole.WriteLine("Multi-Group Mode (Advanced):");
        SystemConsole.WriteLine("  --group-threshold <n>  Number of groups needed to recover (default: 1)");
        SystemConsole.WriteLine("  --groups <config>      Group configurations in format 'threshold-of-total'");
        SystemConsole.WriteLine("                         Examples: \"2-of-3\" or \"2-of-3,3-of-5,1-of-1\"\n");
        
        SystemConsole.WriteLine("Common Options:");
        SystemConsole.WriteLine("  --passphrase <p>   Custom passphrase (default: TREZOR)");
        SystemConsole.WriteLine("  --iterations <n>   Iteration exponent 0-15 (default: 0 = 10,000 iterations)");
        SystemConsole.WriteLine("  --extendable       Generate extendable shares");
        SystemConsole.WriteLine("  --format <fmt>     Output format: text, json, hex (default: text)\n");
        
        SystemConsole.WriteLine("Examples:");
        SystemConsole.WriteLine();
        SystemConsole.WriteLine("  # Simple single group (2-of-3):");
        SystemConsole.WriteLine("  slip39 split --secret 458d0765afec7bb0fb45a50a84d5bf74d75a2b1e69fd79015ce2bb23a9ce9ef3 --threshold 2 --shares 3");
        SystemConsole.WriteLine();
        SystemConsole.WriteLine("  # Multi-group configuration requiring 2 groups:");
        SystemConsole.WriteLine("  slip39 split --secret 1234abcd --group-threshold 2 --groups \"2-of-3,3-of-5,1-of-1\"");
        SystemConsole.WriteLine();
        SystemConsole.WriteLine("  # Advanced: Company backup (2 groups needed: 3-of-5 directors OR 2-of-3 executives):");
        SystemConsole.WriteLine("  slip39 split --secret 1234abcd --group-threshold 1 --groups \"3-of-5,2-of-3\"");
        SystemConsole.WriteLine();
        SystemConsole.WriteLine("  # Bank-style security (3 groups needed: IT + Legal + Management):");
        SystemConsole.WriteLine("  slip39 split --secret 1234abcd --group-threshold 3 --groups \"2-of-3,1-of-2,2-of-4\"");
        SystemConsole.WriteLine();
        SystemConsole.WriteLine("  # With custom passphrase and JSON output:");
        SystemConsole.WriteLine("  slip39 split --secret 1234abcd --groups \"2-of-3\" --passphrase mypass --format json");
    }

    static void HandleCombineCommand(string[] args)
    {
        if (args.Length == 0 || args.Contains("--help"))
        {
            ShowCombineHelp();
            return;
        }

        var shareStrings = new List<string>();
        string? passphrase = null;
        string outputFormat = "hex";
        bool showBip32 = false;

        // Parse arguments
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--shares":
                    // Collect all following arguments until next flag or end
                    i++;
                    while (i < args.Length && !args[i].StartsWith("--"))
                    {
                        shareStrings.Add(args[i]);
                        i++;
                    }
                    i--; // Back up one since the loop will increment
                    break;
                case "--passphrase":
                    passphrase = GetNextArgument(args, ref i, "--passphrase");
                    break;
                case "--format":
                    outputFormat = GetNextArgument(args, ref i, "--format");
                    break;
                case "--bip32":
                    showBip32 = true;
                    break;
                default:
                    // If it doesn't start with --, treat as a share
                    if (!args[i].StartsWith("--"))
                    {
                        shareStrings.Add(args[i]);
                    }
                    break;
            }
        }

        if (shareStrings.Count == 0)
        {
            SystemConsole.WriteLine("Error: At least one share is required");
            return;
        }

        try
        {
            var shares = new List<Slip39Share>();
            
            foreach (var shareString in shareStrings)
            {
                var share = Slip39ShareParser.ParseFromMnemonic(shareString);
                shares.Add(share);
            }

            byte[] masterSecret = Slip39ShareCombination.CombineShares(shares, passphrase);

            SystemConsole.WriteLine("Successfully recovered master secret!");
            SystemConsole.WriteLine();
            
            SystemConsole.WriteLine($"Shares used: {shares.Count}");
            SystemConsole.WriteLine($"Passphrase: {FormatPassphraseDisplay(passphrase)}");
            SystemConsole.WriteLine();

            switch (outputFormat.ToLower())
            {
                case "base64":
                    SystemConsole.WriteLine($"Master Secret (Base64): {Convert.ToBase64String(masterSecret)}");
                    break;
                case "binary":
                    SystemConsole.WriteLine($"Master Secret (Binary): {string.Join("", masterSecret.Select(b => Convert.ToString(b, 2).PadLeft(8, '0')))}");
                    break;
                default:
                    SystemConsole.WriteLine($"Master Secret (Hex): {Convert.ToHexString(masterSecret).ToLowerInvariant()}");
                    break;
            }

            if (showBip32)
            {
                try
                {
                    // Check if this is a 64-byte secret from split-xpriv (private key + chain code)
                    if (masterSecret.Length == 64)
                    {
                        // Reconstruct the original BIP32 extended private key
                        string reconstructedXpriv = ReconstructBip32ExtendedKey(masterSecret);
                        SystemConsole.WriteLine($"Reconstructed BIP32 Extended Private Key: {reconstructedXpriv}");
                    }
                    else
                    {
                        // Generate a new BIP32 master key from the secret
                        string bip32Key = Bip32MasterKey.GenerateMasterKey(masterSecret);
                        SystemConsole.WriteLine($"BIP32 Master Key: {bip32Key}");
                    }
                }
                catch (Exception ex)
                {
                    SystemConsole.WriteLine($"Warning: Could not generate BIP32 key: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            SystemConsole.WriteLine($"Error combining shares: {ex.Message}");
        }
    }

    static void ShowCombineHelp()
    {
        SystemConsole.WriteLine("Combine Command - Combine SLIP-0039 shares to recover secret");
        SystemConsole.WriteLine("==========================================================\n");
        
        SystemConsole.WriteLine("Usage:");
        SystemConsole.WriteLine("  slip39 combine [options] \"share1\" \"share2\" [\"share3\" ...]\n");
        
        SystemConsole.WriteLine("Optional Arguments:");
        SystemConsole.WriteLine("  --shares \"s1\" \"s2\"  List of mnemonic shares to combine");
        SystemConsole.WriteLine("  --passphrase <p>    Custom passphrase (default: TREZOR)");
        SystemConsole.WriteLine("  --format <fmt>      Output format: hex, base64, binary (default: hex)");
        SystemConsole.WriteLine("  --bip32             Also show BIP32 master key\n");
        
        SystemConsole.WriteLine("Examples:");
        SystemConsole.WriteLine("  slip39 combine \"mild isolate academic acid...\" \"mild isolate academic agency...\"");
        SystemConsole.WriteLine("  slip39 combine --passphrase mypass --bip32 \"share1\" \"share2\"");
        SystemConsole.WriteLine("  slip39 combine --format base64 \"share1\" \"share2\"");
    }

    static void HandleInfoCommand(string[] args)
    {
        if (args.Length == 0 || args.Contains("--help"))
        {
            ShowInfoHelp();
            return;
        }

        string shareString = args[0];
        string outputFormat = "text";
        bool validateChecksum = true;

        // Parse additional arguments
        for (int i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--format":
                    outputFormat = GetNextArgument(args, ref i, "--format");
                    break;
                case "--no-validate":
                    validateChecksum = false;
                    break;
            }
        }

        try
        {
            var share = Slip39ShareParser.ParseFromMnemonic(shareString);
            
            if (validateChecksum)
            {
                try
                {
                    Slip39ShareCombination.ValidateChecksums(new List<Slip39Share> { share });
                    SystemConsole.WriteLine("✓ Checksum validation: PASSED\n");
                }
                catch
                {
                    SystemConsole.WriteLine("✗ Checksum validation: FAILED\n");
                }
            }

            switch (outputFormat.ToLower())
            {
                case "json":
                    SystemConsole.WriteLine(Slip39ShareParser.ToJson(share, true));
                    break;
                    
                case "hex":
                    SystemConsole.WriteLine($"Hex representation: {share.ToHex()}");
                    break;
                    
                default:
                    ShowShareInfoText(share);
                    break;
            }
        }
        catch (Exception ex)
        {
            SystemConsole.WriteLine($"Error parsing share: {ex.Message}");
        }
    }

    static void ShowShareInfoText(Slip39Share share)
    {
        SystemConsole.WriteLine("SLIP-0039 Share Information");
        SystemConsole.WriteLine("==========================\n");
        
        SystemConsole.WriteLine($"Identifier: {share.Identifier} (0x{share.Identifier:X4})");
        SystemConsole.WriteLine($"Extendable: {(share.IsExtendable ? "Yes" : "No")}");
        SystemConsole.WriteLine($"Iteration Exponent: {share.IterationExponent}");
        SystemConsole.WriteLine($"Total Iterations: {share.TotalIterations:N0}");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("Group Configuration:");
        SystemConsole.WriteLine($"  Group Index: {share.GroupIndex}");
        SystemConsole.WriteLine($"  Group Threshold: {share.ActualGroupThreshold} (need {share.ActualGroupThreshold} groups)");
        SystemConsole.WriteLine($"  Group Count: {share.ActualGroupCount} (total {share.ActualGroupCount} groups)");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("Member Configuration:");
        SystemConsole.WriteLine($"  Member Index: {share.MemberIndex}");
        SystemConsole.WriteLine($"  Member Threshold: {share.ActualMemberThreshold} (need {share.ActualMemberThreshold} shares from this group)");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("Share Data:");
        SystemConsole.WriteLine($"  Share Value Length: {share.ShareValue.Length} bytes ({share.ShareValue.Length * 8} bits)");
        SystemConsole.WriteLine($"  Share Value: {Convert.ToHexString(share.ShareValue).ToLowerInvariant()}");
        SystemConsole.WriteLine($"  Checksum: {share.Checksum} (0x{share.Checksum:X8})");
        SystemConsole.WriteLine($"  Checksum Type: {share.ChecksumCustomizationString}");
        SystemConsole.WriteLine();
        
        SystemConsole.WriteLine("Recovery Requirements:");
        if (share.ActualGroupCount == 1)
        {
            SystemConsole.WriteLine($"  • Need {share.ActualMemberThreshold} shares from this single group");
        }
        else
        {
            SystemConsole.WriteLine($"  • Need {share.ActualGroupThreshold} groups out of {share.ActualGroupCount} total groups");
            SystemConsole.WriteLine($"  • Need {share.ActualMemberThreshold} shares from each required group");
        }
        
        int estimatedSecretBits = share.ShareValue.Length * 8;
        if (estimatedSecretBits >= 128 && estimatedSecretBits <= 160)
            SystemConsole.WriteLine("  • Estimated original secret size: 128 bits (16 bytes)");
        else if (estimatedSecretBits >= 256 && estimatedSecretBits <= 280)
            SystemConsole.WriteLine("  • Estimated original secret size: 256 bits (32 bytes)");
        else
            SystemConsole.WriteLine($"  • Estimated original secret size: {estimatedSecretBits} bits ({estimatedSecretBits / 8} bytes)");
    }

    static void ShowInfoHelp()
    {
        SystemConsole.WriteLine("Info Command - Display detailed information about a share");
        SystemConsole.WriteLine("========================================================\n");
        
        SystemConsole.WriteLine("Usage:");
        SystemConsole.WriteLine("  slip39 info [options] \"share mnemonic\"\n");
        
        SystemConsole.WriteLine("Optional Arguments:");
        SystemConsole.WriteLine("  --format <fmt>    Output format: text, json, hex (default: text)");
        SystemConsole.WriteLine("  --no-validate     Skip checksum validation\n");
        
        SystemConsole.WriteLine("Examples:");
        SystemConsole.WriteLine("  slip39 info \"mild isolate academic acid apart...\"");
        SystemConsole.WriteLine("  slip39 info --format json \"share mnemonic\"");
        SystemConsole.WriteLine("  slip39 info --no-validate \"potentially invalid share\"");
    }

    static void HandleValidateCommand(string[] args)
    {
        if (args.Length == 0 || args.Contains("--help"))
        {
            ShowValidateHelp();
            return;
        }

        var shareStrings = new List<string>();
        bool verbose = false;

        // Parse arguments
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--verbose":
                    verbose = true;
                    break;
                default:
                    if (!args[i].StartsWith("--"))
                    {
                        shareStrings.Add(args[i]);
                    }
                    break;
            }
        }

        if (shareStrings.Count == 0)
        {
            SystemConsole.WriteLine("Error: At least one share is required");
            return;
        }

        int validCount = 0;
        int totalCount = shareStrings.Count;

        SystemConsole.WriteLine($"Validating {totalCount} shares...\n");

        for (int i = 0; i < shareStrings.Count; i++)
        {
            try
            {
                var share = Slip39ShareParser.ParseFromMnemonic(shareStrings[i]);
                
                try
                {
                    Slip39ShareCombination.ValidateChecksums(new List<Slip39Share> { share });
                    SystemConsole.WriteLine($"Share {i + 1}: ✓ VALID");
                    validCount++;
                    
                    if (verbose)
                    {
                        SystemConsole.WriteLine($"  Identifier: {share.Identifier}");
                        SystemConsole.WriteLine($"  Group: {share.GroupIndex}, Member: {share.MemberIndex}");
                        SystemConsole.WriteLine($"  Checksum: 0x{share.Checksum:X8}\n");
                    }
                }
                catch (Exception ex)
                {
                    SystemConsole.WriteLine($"Share {i + 1}: ✗ INVALID CHECKSUM - {ex.Message}");
                    if (verbose)
                    {
                        SystemConsole.WriteLine($"  Parsed successfully but checksum failed");
                        SystemConsole.WriteLine($"  Identifier: {share.Identifier}");
                        SystemConsole.WriteLine($"  Checksum: 0x{share.Checksum:X8}\n");
                    }
                }
            }
            catch (Exception ex)
            {
                SystemConsole.WriteLine($"Share {i + 1}: ✗ PARSE ERROR - {ex.Message}");
                if (verbose)
                {
                    SystemConsole.WriteLine($"  Could not parse share mnemonic\n");
                }
            }
        }

        SystemConsole.WriteLine($"\nValidation Summary: {validCount}/{totalCount} shares valid");
        
        if (validCount == totalCount)
        {
            SystemConsole.WriteLine("✓ All shares are valid!");
        }
        else
        {
            SystemConsole.WriteLine("⚠ Some shares have validation issues");
            Environment.Exit(1);
        }
    }

    static void ShowValidateHelp()
    {
        SystemConsole.WriteLine("Validate Command - Validate SLIP-0039 share checksums");
        SystemConsole.WriteLine("====================================================\n");
        
        SystemConsole.WriteLine("Usage:");
        SystemConsole.WriteLine("  slip39 validate [options] \"share1\" \"share2\" [\"share3\" ...]\n");
        
        SystemConsole.WriteLine("Optional Arguments:");
        SystemConsole.WriteLine("  --verbose         Show detailed validation information\n");
        
        SystemConsole.WriteLine("Examples:");
        SystemConsole.WriteLine("  slip39 validate \"mild isolate academic acid...\" \"mild isolate academic agency...\"");
        SystemConsole.WriteLine("  slip39 validate --verbose \"share1\" \"share2\" \"share3\"");
    }

    static void HandleGenerateCommand(string[] args)
    {
        if (args.Length == 0 || args.Contains("--help"))
        {
            ShowGenerateHelp();
            return;
        }

        int bits = 256;
        int threshold = 2;
        int shares = 3;
        string? passphrase = null;
        byte iterationExponent = 0;
        bool extendable = false;
        string outputFormat = "text";
        bool showSecret = false;
        bool showBip32 = false;

        // Parse arguments
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--bits":
                    bits = ParseIntArgument(args, ref i, "--bits");
                    break;
                case "--threshold":
                    threshold = ParseIntArgument(args, ref i, "--threshold");
                    break;
                case "--shares":
                    shares = ParseIntArgument(args, ref i, "--shares");
                    break;
                case "--passphrase":
                    passphrase = GetNextArgument(args, ref i, "--passphrase");
                    break;
                case "--iterations":
                    iterationExponent = ParseByteArgument(args, ref i, "--iterations");
                    break;
                case "--extendable":
                    extendable = true;
                    break;
                case "--format":
                    outputFormat = GetNextArgument(args, ref i, "--format");
                    break;
                case "--show-secret":
                    showSecret = true;
                    break;
                case "--bip32":
                    showBip32 = true;
                    break;
            }
        }

        if (bits != 128 && bits != 256)
        {
            SystemConsole.WriteLine("Error: Only 128-bit and 256-bit secrets are supported");
            return;
        }

        try
        {
            // Generate random secret
            byte[] secret = new byte[bits / 8];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(secret);
            }

            SystemConsole.WriteLine($"Generated {bits}-bit random secret and split into shares:");
            SystemConsole.WriteLine($"Threshold: {threshold} shares required to recover");
            SystemConsole.WriteLine($"Total shares: {shares}");
            SystemConsole.WriteLine($"Passphrase: {FormatPassphraseDisplay(passphrase)}");
            SystemConsole.WriteLine();

            if (showSecret)
            {
                SystemConsole.WriteLine($"Secret (Hex): {Convert.ToHexString(secret).ToLowerInvariant()}");
                
                if (showBip32)
                {
                    try
                    {
                        string bip32Key = Bip32MasterKey.GenerateMasterKey(secret);
                        SystemConsole.WriteLine($"BIP32 Master Key: {bip32Key}");
                    }
                    catch (Exception ex)
                    {
                        SystemConsole.WriteLine($"Warning: Could not generate BIP32 key: {ex.Message}");
                    }
                }
                
                SystemConsole.WriteLine();
            }

            var groupConfigs = new List<Slip39ShareGeneration.GroupConfig>
            {
                new(threshold, shares)
            };

            var generatedShares = Slip39ShareGeneration.GenerateShares(
                groupThreshold: 1,
                groupConfigs: groupConfigs,
                masterSecret: secret,
                passphrase: passphrase,
                iterationExponent: iterationExponent,
                isExtendable: extendable
            );

            SystemConsole.WriteLine("Generated shares:");
            SystemConsole.WriteLine();

            DisplayGeneratedShares(generatedShares, outputFormat);

            if (!showSecret)
            {
                SystemConsole.WriteLine("Note: Use --show-secret to display the original secret for verification.");
            }
        }
        catch (Exception ex)
        {
            SystemConsole.WriteLine($"Error generating shares: {ex.Message}");
        }
    }

    static void HandleSplitXprivCommand(string[] args)
    {
        if (args.Length == 0 || args.Contains("--help"))
        {
            ShowSplitXprivHelp();
            return;
        }

        string? xpriv = null;
        int threshold = 2;
        int shares = 3;
        int groupThreshold = 1;
        var groupConfigs = new List<string>();
        string? passphrase = null;
        byte iterationExponent = 0;
        bool extendable = false;
        string outputFormat = "text";
        bool showSecret = false;

        // Parse arguments
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--xpriv":
                    xpriv = GetNextArgument(args, ref i, "--xpriv");
                    break;
                case "--threshold":
                    threshold = ParseIntArgument(args, ref i, "--threshold");
                    break;
                case "--shares":
                    shares = ParseIntArgument(args, ref i, "--shares");
                    break;
                case "--group-threshold":
                    groupThreshold = ParseIntArgument(args, ref i, "--group-threshold");
                    break;
                case "--groups":
                    groupConfigs.Add(GetNextArgument(args, ref i, "--groups"));
                    break;
                case "--passphrase":
                    passphrase = GetNextArgument(args, ref i, "--passphrase");
                    break;
                case "--iterations":
                    iterationExponent = ParseByteArgument(args, ref i, "--iterations");
                    break;
                case "--extendable":
                    extendable = true;
                    break;
                case "--format":
                    outputFormat = GetNextArgument(args, ref i, "--format");
                    break;
                case "--show-secret":
                    showSecret = true;
                    break;
            }
        }

        if (string.IsNullOrEmpty(xpriv))
        {
            SystemConsole.WriteLine("Error: --xpriv is required");
            return;
        }

        try
        {
            // Decode the BIP32 extended private key
            byte[] extendedKeyData = Base58Check.Decode(xpriv);
            
            // Validate BIP32 extended key format
            if (extendedKeyData.Length != 78)
            {
                throw new ArgumentException($"Invalid extended key length: {extendedKeyData.Length} bytes. Expected 78 bytes.");
            }
            
            // Check version bytes (first 4 bytes) for mainnet private key (0x0488ADE4)
            var version = new byte[4];
            Array.Copy(extendedKeyData, 0, version, 0, 4);
            var expectedVersion = new byte[] { 0x04, 0x88, 0xAD, 0xE4 };
            
            if (!version.SequenceEqual(expectedVersion))
            {
                var versionHex = Convert.ToHexString(version);
                SystemConsole.WriteLine($"Warning: Unexpected version bytes: {versionHex}. Expected 0488ADE4 for mainnet xprv.");
            }
            
            // Extract the 32-byte private key (starts at byte 46, after 0x00 prefix at byte 45)
            var privateKey = new byte[32];
            Array.Copy(extendedKeyData, 46, privateKey, 0, 32);
            
            // Extract the 32-byte chain code (bytes 13-44)
            var chainCode = new byte[32];
            Array.Copy(extendedKeyData, 13, chainCode, 0, 32);
            
            // For proper BIP32 reconstruction, we need both the private key and chain code
            // Combine them into a 64-byte secret: private key (32) + chain code (32)
            var masterSecret = new byte[64];
            Array.Copy(privateKey, 0, masterSecret, 0, 32);
            Array.Copy(chainCode, 0, masterSecret, 32, 32);
            
            SystemConsole.WriteLine($"Successfully decoded BIP32 extended private key");
            SystemConsole.WriteLine($"Private Key: {Convert.ToHexString(privateKey).ToLowerInvariant()}");
            SystemConsole.WriteLine($"Chain Code: {Convert.ToHexString(chainCode).ToLowerInvariant()}");
            
            if (showSecret)
            {
                SystemConsole.WriteLine($"Secret to Split: {Convert.ToHexString(masterSecret).ToLowerInvariant()} (private key + chain code)");
            }
            
            SystemConsole.WriteLine();
            
            List<Slip39ShareGeneration.GroupConfig> parsedGroupConfigs;
            
            // If groups are specified, use multi-group configuration
            if (groupConfigs.Count > 0)
            {
                parsedGroupConfigs = ParseGroupConfigurations(groupConfigs);
                
                // Validate group threshold
                if (groupThreshold > parsedGroupConfigs.Count)
                {
                    SystemConsole.WriteLine($"Error: Group threshold ({groupThreshold}) cannot exceed number of groups ({parsedGroupConfigs.Count})");
                    return;
                }
            }
            else
            {
                // Single group configuration (backward compatibility)
                parsedGroupConfigs = new List<Slip39ShareGeneration.GroupConfig>
                {
                    new(threshold, shares)
                };
                groupThreshold = 1;
            }

            // For BIP32 keys, the 64-byte secret (private key + chain code) should be treated
            // as a master secret that goes through the normal SLIP-0039 encryption process
            var generatedShares = Slip39ShareGeneration.GenerateShares(
                groupThreshold: groupThreshold,
                groupConfigs: parsedGroupConfigs,
                masterSecret: masterSecret,
                passphrase: passphrase,
                iterationExponent: iterationExponent,
                isExtendable: extendable
            );

            // Display configuration summary
            SystemConsole.WriteLine($"Successfully generated {generatedShares.Count} SLIP-0039 shares from BIP32 key:");
            
            if (parsedGroupConfigs.Count == 1)
            {
                SystemConsole.WriteLine($"Single Group: {threshold} of {shares} shares required to recover");
            }
            else
            {
                SystemConsole.WriteLine($"Multi-Group Configuration: {groupThreshold} groups required out of {parsedGroupConfigs.Count} total groups");
                for (int i = 0; i < parsedGroupConfigs.Count; i++)
                {
                    var config = parsedGroupConfigs[i];
                    SystemConsole.WriteLine($"  Group {i + 1}: {config.MemberThreshold} of {config.MemberCount} shares");
                }
            }
            
            SystemConsole.WriteLine($"Passphrase: {FormatPassphraseDisplay(passphrase)}");
            SystemConsole.WriteLine();

            DisplayGeneratedShares(generatedShares, outputFormat);
            
            SystemConsole.WriteLine("Note: To recover the original BIP32 key, combine the shares and use the 'combine --bip32' command.");
        }
        catch (Exception ex)
        {
            SystemConsole.WriteLine($"Error processing BIP32 extended private key: {ex.Message}");
        }
    }
    
    static void ShowSplitXprivHelp()
    {
        SystemConsole.WriteLine("Split-Xpriv Command - Split a BIP32 extended private key into SLIP-0039 shares");
        SystemConsole.WriteLine("===============================================================================\n");
        
        SystemConsole.WriteLine("Usage:");
        SystemConsole.WriteLine("  slip39 split-xpriv --xpriv <xprv...> [options]\n");
        
        SystemConsole.WriteLine("Required Arguments:");
        SystemConsole.WriteLine("  --xpriv <xprv...>   BIP32 extended private key (starts with 'xprv')\n");
        
        SystemConsole.WriteLine("Single Group Mode (Simple):");
        SystemConsole.WriteLine("  --threshold <n>     Number of shares needed to recover (default: 2)");
        SystemConsole.WriteLine("  --shares <n>        Total number of shares to generate (default: 3)\n");
        
        SystemConsole.WriteLine("Multi-Group Mode (Advanced):");
        SystemConsole.WriteLine("  --group-threshold <n>  Number of groups needed to recover (default: 1)");
        SystemConsole.WriteLine("  --groups <config>      Group configurations in format 'threshold-of-total'");
        SystemConsole.WriteLine("                         Examples: \"2-of-3\" or \"2-of-3,3-of-5,1-of-1\"\n");
        
        SystemConsole.WriteLine("Common Options:");
        SystemConsole.WriteLine("  --passphrase <p>    Custom passphrase (default: TREZOR)");
        SystemConsole.WriteLine("  --iterations <n>    Iteration exponent 0-15 (default: 0 = 10,000 iterations)");
        SystemConsole.WriteLine("  --extendable        Generate extendable shares");
        SystemConsole.WriteLine("  --format <fmt>      Output format: text, json, hex (default: text)");
        SystemConsole.WriteLine("  --show-secret       Display the extracted secret components\n");
        
        SystemConsole.WriteLine("Examples:");
        SystemConsole.WriteLine();
        SystemConsole.WriteLine("  # Simple backup of hardware wallet master key:");
        SystemConsole.WriteLine("  slip39 split-xpriv --xpriv xprv9s21ZrQH... --threshold 2 --shares 3");
        SystemConsole.WriteLine();
        SystemConsole.WriteLine("  # Multi-signature wallet backup:");
        SystemConsole.WriteLine("  slip39 split-xpriv --xprv xprv9s21ZrQH... --group-threshold 2 --groups \"2-of-3,3-of-5\"");
        SystemConsole.WriteLine();
        SystemConsole.WriteLine("  # Corporate backup with custom passphrase:");
        SystemConsole.WriteLine("  slip39 split-xpriv --xprv xprv9s21ZrQH... --groups \"3-of-5\" --passphrase corp2024");
        SystemConsole.WriteLine();
        SystemConsole.WriteLine("Note: The resulting shares can be combined using 'slip39 combine --bip32' to reconstruct the original xprv.");
    }

    static void ShowGenerateHelp()
    {
        SystemConsole.WriteLine("Generate Command - Generate random secret and split into shares");
        SystemConsole.WriteLine("===============================================================\n");
        
        SystemConsole.WriteLine("Usage:");
        SystemConsole.WriteLine("  slip39 generate [options]\n");
        
        SystemConsole.WriteLine("Optional Arguments:");
        SystemConsole.WriteLine("  --bits \u003cn\u003e         Secret size in bits: 128 or 256 (default: 256)");
        SystemConsole.WriteLine("  --threshold \u003cn\u003e    Number of shares needed to recover (default: 2)");
        SystemConsole.WriteLine("  --shares \u003cn\u003e       Total number of shares to generate (default: 3)");
        SystemConsole.WriteLine("  --passphrase \u003cp\u003e   Custom passphrase (default: TREZOR)");
        SystemConsole.WriteLine("  --iterations \u003cn\u003e   Iteration exponent 0-15 (default: 0 = 10,000 iterations)");
        SystemConsole.WriteLine("  --extendable       Generate extendable shares");
        SystemConsole.WriteLine("  --format \u003cfmt\u003e     Output format: text, json, hex (default: text)");
        SystemConsole.WriteLine("  --show-secret      Display the generated secret (for verification)");
        SystemConsole.WriteLine("  --bip32            Also show BIP32 master key\n");
        
        SystemConsole.WriteLine("Examples:");
        SystemConsole.WriteLine("  slip39 generate");
        SystemConsole.WriteLine("  slip39 generate --bits 128 --threshold 3 --shares 5");
        SystemConsole.WriteLine("  slip39 generate --show-secret --bip32");
        SystemConsole.WriteLine("  slip39 generate --passphrase mypass --format json");
    }

    // Helper methods for argument parsing
    static string GetNextArgument(string[] args, ref int index, string paramName)
    {
        if (index + 1 >= args.Length)
            throw new ArgumentException($"Missing value for {paramName}");
        return args[++index];
    }

    static int ParseIntArgument(string[] args, ref int index, string paramName)
    {
        string value = GetNextArgument(args, ref index, paramName);
        if (!int.TryParse(value, out int result))
            throw new ArgumentException($"Invalid integer value for {paramName}: {value}");
        return result;
    }

    static byte ParseByteArgument(string[] args, ref int index, string paramName)
    {
        string value = GetNextArgument(args, ref index, paramName);
        if (!byte.TryParse(value, out byte result))
            throw new ArgumentException($"Invalid byte value for {paramName}: {value}");
        return result;
    }

    static string FormatShareOutput(Slip39Share share, string format)
    {
        return format.ToLower() switch
        {
            "json" => Slip39ShareParser.ToJson(share),
            "hex" => share.ToHex(),
            _ => share.ToMnemonic()
        };
    }

    static string FormatPassphraseDisplay(string? passphrase)
    {
        return string.IsNullOrEmpty(passphrase) ? "TREZOR (default)" : "[custom]";
    }

    static void DisplayGeneratedShares(List<Slip39Share> shares, string outputFormat)
    {
        // Group shares by group for better display
        var sharesByGroup = shares.GroupBy(s => s.GroupIndex).OrderBy(g => g.Key).ToList();
        
        foreach (var group in sharesByGroup)
        {
            bool isMultiGroup = sharesByGroup.Count > 1;
            if (isMultiGroup)
            {
                SystemConsole.WriteLine($"Group {group.Key + 1} shares:");
            }
            
            foreach (var share in group.OrderBy(s => s.MemberIndex))
            {
                string prefix = isMultiGroup ? "  " : "";
                SystemConsole.WriteLine($"{prefix}Share {share.MemberIndex + 1}:");
                
                string shareOutput = FormatShareOutput(share, outputFormat);
                SystemConsole.WriteLine($"{prefix}{shareOutput}");
                SystemConsole.WriteLine();
            }
            
            if (isMultiGroup)
            {
                SystemConsole.WriteLine();
            }
        }
    }
    
    /// <summary>
    /// Reconstructs a BIP32 extended private key from a 64-byte master secret
    /// (32-byte private key + 32-byte chain code)
    /// </summary>
    static string ReconstructBip32ExtendedKey(byte[] masterSecret)
    {
        if (masterSecret.Length != 64)
        {
            throw new ArgumentException($"Master secret must be 64 bytes for BIP32 reconstruction, got {masterSecret.Length} bytes");
        }
        
        // Extract the private key and chain code
        var privateKey = new byte[32];
        var chainCode = new byte[32];
        Array.Copy(masterSecret, 0, privateKey, 0, 32);
        Array.Copy(masterSecret, 32, chainCode, 0, 32);
        
        // Build BIP32 extended private key structure (78 bytes total)
        var extendedKey = new byte[78];
        int offset = 0;
        
        // Version (4 bytes): 0x0488ADE4 for mainnet private key
        var mainnetPrivateVersion = new byte[] { 0x04, 0x88, 0xAD, 0xE4 };
        Array.Copy(mainnetPrivateVersion, 0, extendedKey, offset, 4);
        offset += 4;
        
        // Depth (1 byte): 0x00 for master key
        extendedKey[offset] = 0x00;
        offset += 1;
        
        // Parent fingerprint (4 bytes): 0x00000000 for master key
        Array.Clear(extendedKey, offset, 4);
        offset += 4;
        
        // Child number (4 bytes): 0x00000000 for master key
        Array.Clear(extendedKey, offset, 4);
        offset += 4;
        
        // Chain code (32 bytes)
        Array.Copy(chainCode, 0, extendedKey, offset, 32);
        offset += 32;
        
        // Private key (33 bytes): 0x00 prefix + 32-byte private key
        extendedKey[offset] = 0x00; // Private key prefix
        offset += 1;
        Array.Copy(privateKey, 0, extendedKey, offset, 32);
        
        // Encode with Base58Check
        return Base58Check.Encode(extendedKey);
    }
}
