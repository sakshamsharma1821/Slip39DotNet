using System.Security.Cryptography;
using System.Text;

namespace Slip39.Core;

/// <summary>
/// Implements the SLIP-0039 master secret encryption and decryption algorithms.
/// Uses a four-round Feistel network with PBKDF2 as the round function.
/// Reimplemented based on JS reference implementation.
/// </summary>
public static class Slip39Encryption
{
    private const int ROUND_COUNT = 4;
    private const int BASE_ITERATION_COUNT = 10000;
    /// <summary>
    /// Encrypts a master secret using the SLIP-0039 encryption algorithm.
    /// </summary>
    /// <param name="masterSecret">The master secret to encrypt</param>
    /// <param name="passphrase">The passphrase for encryption (null defaults to "TREZOR")</param>
    /// <param name="iterationExponent">The iteration exponent (e)</param>
    /// <param name="identifier">The random identifier (id)</param>
    /// <param name="isExtendable">The extendable backup flag</param>
    /// <returns>The encrypted master secret</returns>
    /// <exception cref="ArgumentException">Thrown when parameters are invalid</exception>
    public static byte[] Encrypt(byte[] masterSecret, string? passphrase, byte iterationExponent, 
        ushort identifier, bool isExtendable)
    {
        // Validate arguments
        if (masterSecret == null)
            throw new ArgumentNullException(nameof(masterSecret));
        if (masterSecret.Length < 16)
            throw new ArgumentException("Master secret must be at least 16 bytes", nameof(masterSecret));
        if (masterSecret.Length % 2 != 0)
            throw new ArgumentException("Master secret length must be even", nameof(masterSecret));
        if (iterationExponent > 15)
            throw new ArgumentException("Iteration exponent must be 4 bits or less", nameof(iterationExponent));
        if (identifier > 0x7FFF)
            throw new ArgumentException("Identifier must be 15 bits or less", nameof(identifier));
        
        return Crypt(identifier, iterationExponent, masterSecret, new byte[] {0, 1, 2, 3}, passphrase, isExtendable);
    }
    
    /// <summary>
    /// Decrypts an encrypted master secret using the SLIP-0039 decryption algorithm.
    /// </summary>
    /// <param name="encryptedMasterSecret">The encrypted master secret to decrypt</param>
    /// <param name="passphrase">The passphrase for decryption (null defaults to "TREZOR")</param>
    /// <param name="iterationExponent">The iteration exponent (e)</param>
    /// <param name="identifier">The random identifier (id)</param>
    /// <param name="isExtendable">The extendable backup flag</param>
    /// <returns>The decrypted master secret</returns>
    /// <exception cref="ArgumentException">Thrown when parameters are invalid</exception>
    public static byte[] Decrypt(byte[] encryptedMasterSecret, string? passphrase, byte iterationExponent,
        ushort identifier, bool isExtendable)
    {
        // Validate arguments
        if (encryptedMasterSecret == null)
            throw new ArgumentNullException(nameof(encryptedMasterSecret));
        if (encryptedMasterSecret.Length < 16)
            throw new ArgumentException("Encrypted master secret must be at least 16 bytes", nameof(encryptedMasterSecret));
        if (encryptedMasterSecret.Length % 2 != 0)
            throw new ArgumentException("Encrypted master secret length must be even", nameof(encryptedMasterSecret));
        if (iterationExponent > 15)
            throw new ArgumentException("Iteration exponent must be 4 bits or less", nameof(iterationExponent));
        if (identifier > 0x7FFF)
            throw new ArgumentException("Identifier must be 15 bits or less", nameof(identifier));
        
        return Crypt(identifier, iterationExponent, encryptedMasterSecret, new byte[] {3, 2, 1, 0}, passphrase, isExtendable);
    }
    
    /// <summary>
    /// Core Feistel network implementation matching reference
    /// </summary>
    private static byte[] Crypt(int identifier, int iterationExponent, byte[] masterSecret, byte[] range, string? passphrase, bool extendable)
    {
        int len = masterSecret.Length / 2;
        byte[] left = new byte[len];
        byte[] right = new byte[len];
        
        Array.Copy(masterSecret, 0, left, 0, len);
        Array.Copy(masterSecret, len, right, 0, len);
        
        foreach (byte i in range)
        {
            byte[] f = Feistel(identifier, iterationExponent, i, right, passphrase, extendable);
            var newLeft = right;
            right = XorBytes(left, f);
            left = newLeft;
        }
        
        // Return right || left
        var result = new byte[masterSecret.Length];
        Array.Copy(right, 0, result, 0, len);
        Array.Copy(left, 0, result, len, len);
        return result;
    }
    
    /// <summary>
    /// Feistel function matching reference implementation exactly
    /// </summary>
    private static byte[] Feistel(int id, int iterationExponent, byte step, byte[] block, string? passphrase, bool extendable)
    {
        // Check passphrase for printable ASCII only (like reference implementation)
        // Passphrase validation removed - Unicode normalization handles encoding
        
        // Key = step || passphrase bytes (with Unicode normalization as per SLIP-0039 spec)
        var passphraseBytes = Slip39Passphrase.NormalizePassphrase(passphrase);
        byte[] key = ArrayConcat(new byte[] { step }, passphraseBytes);
        
        // Salt prefix = "shamir" + identifier bytes (or empty if extendable)
        byte[] saltPrefix = extendable ? new byte[0] : ArrayConcat(Encoding.UTF8.GetBytes("shamir"), new byte[] { (byte)(id >> 8), (byte)(id & 0xff) });
        
        // Salt = saltPrefix || block
        byte[] salt = ArrayConcat(saltPrefix, block);
        
        // Iterations = (BASE_ITERATION_COUNT / ROUND_COUNT) << iterationExponent
        int iters = (BASE_ITERATION_COUNT / ROUND_COUNT) << iterationExponent;
        
        using var pbkdf2 = new Rfc2898DeriveBytes(key, salt, iters, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(block.Length);
    }
    
    
    /// <summary>
    /// Concatenate two arrays.
    /// </summary>
    private static T[] ArrayConcat<T>(T[] first, T[] second)
    {
        T[] result = new T[first.Length + second.Length];
        Array.Copy(first, 0, result, 0, first.Length);
        Array.Copy(second, 0, result, first.Length, second.Length);
        return result;
    }
    
    /// <summary>
    /// XOR two byte arrays of equal length.
    /// </summary>
    /// <param name="a">First byte array</param>
    /// <param name="b">Second byte array</param>
    /// <returns>XOR result</returns>
    /// <exception cref="ArgumentException">Thrown when arrays have different lengths</exception>
    private static byte[] XorBytes(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
            throw new ArgumentException("Arrays must have the same length");
        
        var result = new byte[a.Length];
        for (int i = 0; i < a.Length; i++)
            result[i] = (byte)(a[i] ^ b[i]);
        
        return result;
    }
    
    /// <summary>
    /// Check passphrase for printable ASCII characters only (matching reference implementation)
    /// Note: This method is now disabled to allow Unicode passphrases with normalization
    /// </summary>
    private static string CheckPassphrase(string passphrase)
    {
        // Unicode passphrases are allowed and will be normalized
        // Only check for null/empty
        if (passphrase == null)
            throw new ArgumentNullException(nameof(passphrase));
        return passphrase;
    }
}
