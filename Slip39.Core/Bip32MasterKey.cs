using System.Security.Cryptography;
using System.Text;

namespace Slip39.Core;

/// <summary>
/// BIP32 master key derivation and encoding according to SLIP-0039 specification.
/// Implements the conversion from SLIP-0039 master secret to BIP32 extended private key format.
/// </summary>
public static class Bip32MasterKey
{
    // BIP32 version bytes for mainnet extended private key
    private static readonly byte[] MAINNET_PRIVATE_VERSION = { 0x04, 0x88, 0xAD, 0xE4 };
    
    // BIP32 constants
    private const int EXTENDED_KEY_LENGTH = 78;
    private const int CHAIN_CODE_LENGTH = 32;
    private const int PRIVATE_KEY_LENGTH = 32;

    /// <summary>
    /// Generates a BIP32 extended private key from a SLIP-0039 master secret according to the specification.
    /// </summary>
    /// <param name="masterSecret">The master secret recovered from SLIP-0039 shares</param>
    /// <param name="passphrase">Optional passphrase (default is "TREZOR")</param>
    /// <returns>Base58Check encoded BIP32 extended private key (xprv...)</returns>
    public static string GenerateMasterKey(byte[] masterSecret, string? passphrase = null)
    {
        if (masterSecret == null)
            throw new ArgumentNullException(nameof(masterSecret));
        
        // Use master secret directly as seed for BIP32 derivation
        // The passphrase was already used during SLIP-0039 decryption
        var seed = masterSecret;
        
        // Derive master key using HMAC-SHA512 with "Bitcoin seed" as per SLIP-0039 specification
        using var hmac = new HMACSHA512(Encoding.UTF8.GetBytes("Bitcoin seed"));
        var hash = hmac.ComputeHash(seed);
        
        // Split the 64-byte hash into 32-byte private key and 32-byte chain code
        var privateKey = new byte[PRIVATE_KEY_LENGTH];
        var chainCode = new byte[CHAIN_CODE_LENGTH];
        
        Array.Copy(hash, 0, privateKey, 0, PRIVATE_KEY_LENGTH);
        Array.Copy(hash, PRIVATE_KEY_LENGTH, chainCode, 0, CHAIN_CODE_LENGTH);
        
        // Build BIP32 extended private key structure
        var extendedKey = new byte[EXTENDED_KEY_LENGTH];
        int offset = 0;
        
        // Version (4 bytes): 0x0488ADE4 for mainnet private key
        Array.Copy(MAINNET_PRIVATE_VERSION, 0, extendedKey, offset, 4);
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
        Array.Copy(chainCode, 0, extendedKey, offset, CHAIN_CODE_LENGTH);
        offset += CHAIN_CODE_LENGTH;
        
        // Private key (33 bytes): 0x00 prefix + 32-byte private key
        extendedKey[offset] = 0x00; // Private key prefix
        offset += 1;
        Array.Copy(privateKey, 0, extendedKey, offset, PRIVATE_KEY_LENGTH);
        
        // Encode with Base58Check
        return Base58Check.Encode(extendedKey);
    }
}

/// <summary>
/// Base58Check encoding implementation for BIP32 extended keys.
/// </summary>
public static class Base58Check
{
    private const string Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    
    /// <summary>
    /// Encodes data with Base58Check (includes SHA256 double hash checksum).
    /// </summary>
    /// <param name="data">Data to encode</param>
    /// <returns>Base58Check encoded string</returns>
    public static string Encode(byte[] data)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));
        
        // Calculate checksum (first 4 bytes of double SHA256)
        using var sha256 = SHA256.Create();
        var hash1 = sha256.ComputeHash(data);
        var hash2 = sha256.ComputeHash(hash1);
        var checksum = new byte[4];
        Array.Copy(hash2, 0, checksum, 0, 4);
        
        // Combine data + checksum
        var dataWithChecksum = new byte[data.Length + 4];
        Array.Copy(data, 0, dataWithChecksum, 0, data.Length);
        Array.Copy(checksum, 0, dataWithChecksum, data.Length, 4);
        
        // Convert to Base58
        return EncodeBase58(dataWithChecksum);
    }
    
    /// <summary>
    /// Decodes a Base58Check string back to the original data.
    /// </summary>
    /// <param name="encoded">Base58Check encoded string</param>
    /// <returns>Original data without checksum</returns>
    /// <exception cref="ArgumentException">Thrown when checksum is invalid</exception>
    public static byte[] Decode(string encoded)
    {
        if (string.IsNullOrEmpty(encoded))
            throw new ArgumentNullException(nameof(encoded));
        
        var dataWithChecksum = DecodeBase58(encoded);
        
        if (dataWithChecksum.Length < 4)
            throw new ArgumentException("Invalid Base58Check data: too short");
        
        // Split data and checksum
        var data = new byte[dataWithChecksum.Length - 4];
        var checksum = new byte[4];
        Array.Copy(dataWithChecksum, 0, data, 0, data.Length);
        Array.Copy(dataWithChecksum, data.Length, checksum, 0, 4);
        
        // Verify checksum
        using var sha256 = SHA256.Create();
        var hash1 = sha256.ComputeHash(data);
        var hash2 = sha256.ComputeHash(hash1);
        var expectedChecksum = new byte[4];
        Array.Copy(hash2, 0, expectedChecksum, 0, 4);
        
        if (!checksum.SequenceEqual(expectedChecksum))
            throw new ArgumentException("Invalid Base58Check data: checksum mismatch");
        
        return data;
    }
    
    private static string EncodeBase58(byte[] data)
    {
        // Count leading zeros
        int leadingZeros = 0;
        for (int i = 0; i < data.Length && data[i] == 0; i++)
            leadingZeros++;
        
        // Convert to base 58
        var result = new List<char>();
        var copy = new byte[data.Length];
        Array.Copy(data, copy, data.Length);
        
        while (copy.Any(b => b != 0))
        {
            int remainder = 0;
            for (int i = 0; i < copy.Length; i++)
            {
                int temp = remainder * 256 + copy[i];
                copy[i] = (byte)(temp / 58);
                remainder = temp % 58;
            }
            result.Insert(0, Base58Alphabet[remainder]);
        }
        
        // Add leading '1's for leading zeros
        for (int i = 0; i < leadingZeros; i++)
            result.Insert(0, '1');
        
        return new string(result.ToArray());
    }
    
    private static byte[] DecodeBase58(string encoded)
    {
        // Count leading '1's
        int leadingOnes = 0;
        for (int i = 0; i < encoded.Length && encoded[i] == '1'; i++)
            leadingOnes++;
        
        // Convert from base 58
        var result = new List<byte> { 0 };
        
        for (int i = leadingOnes; i < encoded.Length; i++)
        {
            int carry = Base58Alphabet.IndexOf(encoded[i]);
            if (carry < 0)
                throw new ArgumentException($"Invalid Base58 character: {encoded[i]}");
            
            for (int j = 0; j < result.Count; j++)
            {
                carry += result[j] * 58;
                result[j] = (byte)(carry & 0xFF);
                carry >>= 8;
            }
            
            while (carry > 0)
            {
                result.Add((byte)(carry & 0xFF));
                carry >>= 8;
            }
        }
        
        // Add leading zeros for leading '1's
        var finalResult = new byte[leadingOnes + result.Count];
        for (int i = 0; i < leadingOnes; i++)
            finalResult[i] = 0;
        
        // Reverse the result (it was built backwards)
        for (int i = 0; i < result.Count; i++)
            finalResult[leadingOnes + i] = result[result.Count - 1 - i];
        
        return finalResult;
    }
}
