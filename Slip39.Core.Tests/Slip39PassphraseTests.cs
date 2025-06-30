using System.Text;
using Xunit;

namespace Slip39.Core.Tests;

/// <summary>
/// Unit tests for SLIP-0039 passphrase normalization and handling.
/// Verifies compliance with SLIP-0039 specification.
/// </summary>
public class Slip39PassphraseTests
{
    [Fact]
    public void NormalizePassphrase_EmptyString_ShouldReturnTrezorDefault()
    {
        // Act
        var result = Slip39Passphrase.NormalizePassphrase("");

        // Assert
        var expectedTrezor = Encoding.UTF8.GetBytes("TREZOR");
        Assert.Equal(expectedTrezor, result);
    }

    [Fact]
    public void NormalizePassphrase_NullString_ShouldReturnTrezorDefault()
    {
        // Act
        var result = Slip39Passphrase.NormalizePassphrase(null);

        // Assert
        var expectedTrezor = Encoding.UTF8.GetBytes("TREZOR");
        Assert.Equal(expectedTrezor, result);
    }

    [Fact]
    public void NormalizePassphrase_UnicodeCharacters_ShouldBeNormalized()
    {
        // Arrange
        var input = "Å̈"; // Angstrom with combining diaeresis
        
        // Act
        var normalized = Slip39Passphrase.NormalizePassphrase(input);

        // Assert
        // NFKD normalization decomposes characters fully
        var expectedNormalized = input.Normalize(NormalizationForm.FormKD);
        Assert.Equal(Encoding.UTF8.GetBytes(expectedNormalized), normalized);
    }

    [Fact]
    public void ValidatePassphrase_ValidUnicode_ShouldReturnTrue()
    {
        // Arrange
        var input = "Å̈BCDℱ"; 

        // Act
        var isValid = Slip39Passphrase.ValidatePassphrase(input);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void ValidatePassphrase_InvalidControlCharacters_ShouldReturnFalse()
    {
        // Arrange
        var input = "Valid text \u007F"; // DEL control character

        // Act
        var isValid = Slip39Passphrase.ValidatePassphrase(input);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void PreparePassphrase_InvalidPassphrase_ShouldThrow()
    {
        // Arrange
        var input = "Valid text \u007F"; // DEL control character

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39Passphrase.PreparePassphrase(input));
    }

    [Fact]
    public void ArePassphrasesEqual_DifferentNormalizationForms_ShouldReturnTrue()
    {
        // Arrange
        var passphrase1 = "e\u0301"; // 'e' with combining acute accent
        var passphrase2 = "é";       // single character é

        // Act
        var areEqual = Slip39Passphrase.ArePassphrasesEqual(passphrase1, passphrase2);

        // Assert
        Assert.True(areEqual);
    }

    [Fact]
    public void EstimatePassphraseEntropy_VariousCharacters_ShouldProvideReasonableEstimate()
    {
        // Arrange
        var passphrase = "abcDEF123!@#\u2764"; // Includes Unicode heart

        // Act
        var entropy = Slip39Passphrase.EstimatePassphraseEntropy(passphrase);

        // Assert
        Assert.True(entropy > 0);
    }
    
    [Fact]
    public void PreparePassphrase_ValidPassphrase_ShouldReturnCompleteInfo()
    {
        // Arrange
        var passphrase = "Hello World";
        
        // Act
        var info = Slip39Passphrase.PreparePassphrase(passphrase);
        
        // Assert
        Assert.Equal(passphrase, info.Original);
        Assert.Equal(passphrase.Length, info.OriginalLength);
        Assert.Equal(Encoding.UTF8.GetBytes(passphrase), info.NormalizedBytes);
        Assert.Equal(Encoding.UTF8.GetBytes(passphrase).Length, info.NormalizedByteLength);
    }
    
    [Fact]
    public void ValidatePassphrase_CommonWhitespace_ShouldBeValid()
    {
        // Arrange
        var passphrase = "Hello\tWorld\nTest\r";
        
        // Act
        var isValid = Slip39Passphrase.ValidatePassphrase(passphrase);
        
        // Assert
        Assert.True(isValid);
    }
    
    [Fact]
    public void ValidatePassphrase_ExtremelyLongPassphrase_ShouldBeFalse()
    {
        // Arrange
        var longPassphrase = new string('a', 1001); // Exceeds 1000 character limit
        
        // Act
        var isValid = Slip39Passphrase.ValidatePassphrase(longPassphrase);
        
        // Assert
        Assert.False(isValid);
    }
    
    [Fact]
    public void ArePassphrasesEqual_NullAndEmpty_ShouldReturnTrue()
    {
        // Act - Both null and empty should resolve to "TREZOR" default
        var areEqual = Slip39Passphrase.ArePassphrasesEqual(null, "");
        
        // Assert
        Assert.True(areEqual);
    }
    
    [Fact]
    public void EstimatePassphraseEntropy_EmptyPassphrase_ShouldReturnZero()
    {
        // Act - Empty passphrase should be treated as null for entropy estimation
        var entropy = Slip39Passphrase.EstimatePassphraseEntropy("");
        
        // Assert - Empty input to entropy estimation returns 0
        Assert.Equal(0.0, entropy);
    }
    
    [Fact]
    public void EstimatePassphraseEntropy_LowercaseOnly_ShouldReturnReasonableEntropy()
    {
        // Arrange
        var passphrase = "lowercase";
        
        // Act
        var entropy = Slip39Passphrase.EstimatePassphraseEntropy(passphrase);
        
        // Assert
        // Should be approximately passphrase.Length * log2(26)
        var expectedEntropy = passphrase.Length * Math.Log2(26);
        Assert.True(Math.Abs(entropy - expectedEntropy) < 0.1);
    }
    
    [Fact]
    public void PassphraseWithEncryption_DifferentNormalizedForms_ShouldProduceSameResult()
    {
        // Arrange
        var passphrase1 = "e\u0301"; // 'e' with combining acute accent
        var passphrase2 = "é";       // single character é
        var masterSecret = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        ushort identifier = 123;
        byte iterationExponent = 0;
        bool isExtendable = false;
        
        // Act
        var encrypted1 = Slip39Encryption.Encrypt(masterSecret, passphrase1, iterationExponent, identifier, isExtendable);
        var encrypted2 = Slip39Encryption.Encrypt(masterSecret, passphrase2, iterationExponent, identifier, isExtendable);
        
        // Assert
        Assert.Equal(encrypted1, encrypted2);
    }
    
    [Fact]
    public void PassphraseWithEncryption_DecryptionWithNormalizedForm_ShouldWork()
    {
        // Arrange
        var originalPassphrase = "e\u0301"; // 'e' with combining acute accent
        var decryptPassphrase = "é";       // single character é (normalized form)
        var masterSecret = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        ushort identifier = 123;
        byte iterationExponent = 0;
        bool isExtendable = false;
        
        // Act
        var encrypted = Slip39Encryption.Encrypt(masterSecret, originalPassphrase, iterationExponent, identifier, isExtendable);
        var decrypted = Slip39Encryption.Decrypt(encrypted, decryptPassphrase, iterationExponent, identifier, isExtendable);
        
        // Assert
        Assert.Equal(masterSecret, decrypted);
    }
    
    [Theory]
    [InlineData("")]
    [InlineData("simple")]
    [InlineData("Test123!@#")]
    [InlineData("Ελληνικά")]  // Greek
    [InlineData("日本語")]      // Japanese
    [InlineData("🔐🚀")]       // Emojis
    public void PassphraseNormalization_VariousInputs_ShouldBeConsistent(string passphrase)
    {
        // Act
        var normalized1 = Slip39Passphrase.NormalizePassphrase(passphrase);
        var normalized2 = Slip39Passphrase.NormalizePassphrase(passphrase);
        
        // Assert
        Assert.Equal(normalized1, normalized2);
    }
}

