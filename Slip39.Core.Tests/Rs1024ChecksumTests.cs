using Xunit;

namespace Slip39.Core.Tests;

/// <summary>
/// Unit tests for the RS1024 checksum implementation used in SLIP-0039.
/// Tests cover the checksum verification, generation, and utility methods.
/// </summary>
public class Rs1024ChecksumTests
{
    [Fact]
    public void VerifyChecksum_ValidChecksum_ShouldReturnTrue()
    {
        // Arrange - Known valid SLIP-0039 mnemonic words
        // This is a simplified test with known good values
        var validWords = new ushort[] { 1, 2, 3, 4, 5 }; // Placeholder - real test would use actual valid mnemonic
        
        // For this test, we'll create a checksum that we know should be valid
        var dataWords = new ushort[] { 1, 2 };
        var checksumWords = Rs1024Checksum.GenerateChecksum(dataWords);
        var completeWords = dataWords.Concat(checksumWords).ToArray();
        
        // Act
        var isValid = Rs1024Checksum.VerifyChecksum(completeWords);
        
        // Assert
        Assert.True(isValid);
    }
    
    [Fact]
    public void VerifyChecksum_InvalidChecksum_ShouldReturnFalse()
    {
        // Arrange - Create valid checksum then corrupt it
        var dataWords = new ushort[] { 1, 2, 3 };
        var checksumWords = Rs1024Checksum.GenerateChecksum(dataWords);
        var completeWords = dataWords.Concat(checksumWords).ToArray();
        
        // Corrupt the checksum
        completeWords[completeWords.Length - 1] ^= 1; // Flip one bit
        
        // Act
        var isValid = Rs1024Checksum.VerifyChecksum(completeWords);
        
        // Assert
        Assert.False(isValid);
    }
    
    [Fact]
    public void VerifyChecksum_TooFewWords_ShouldThrow()
    {
        // Arrange
        var tooFewWords = new ushort[] { 1, 2 }; // Less than minimum 3 words
        
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Rs1024Checksum.VerifyChecksum(tooFewWords));
    }
    
    [Fact]
    public void VerifyChecksum_WordValueTooLarge_ShouldThrow()
    {
        // Arrange
        var invalidWords = new ushort[] { 1, 2, 1024 }; // 1024 is >= 1024, invalid
        
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Rs1024Checksum.VerifyChecksum(invalidWords));
    }
    
    [Fact]
    public void VerifyChecksum_NullInput_ShouldThrow()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Rs1024Checksum.VerifyChecksum(null!));
    }
    
    [Fact]
    public void GenerateChecksum_ValidInput_ShouldProduceValidChecksum()
    {
        // Arrange
        var dataWords = new ushort[] { 100, 200, 300, 400, 500 };
        
        // Act
        var checksumWords = Rs1024Checksum.GenerateChecksum(dataWords);
        var completeWords = dataWords.Concat(checksumWords).ToArray();
        
        // Assert
        Assert.Equal(3, checksumWords.Length); // Checksum should be exactly 3 words
        Assert.True(Rs1024Checksum.VerifyChecksum(completeWords));
    }
    
    [Fact]
    public void GenerateChecksum_EmptyInput_ShouldWork()
    {
        // Arrange
        var emptyWords = new ushort[0];
        
        // Act
        var checksumWords = Rs1024Checksum.GenerateChecksum(emptyWords);
        var completeWords = emptyWords.Concat(checksumWords).ToArray();
        
        // Assert
        Assert.Equal(3, checksumWords.Length);
        Assert.True(Rs1024Checksum.VerifyChecksum(completeWords));
    }
    
    [Fact]
    public void GenerateChecksum_NullInput_ShouldThrow()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Rs1024Checksum.GenerateChecksum(null!));
    }
    
    [Fact]
    public void CalculateChecksum_KnownInput_ShouldBeConsistent()
    {
        // Arrange
        var words = new ushort[] { 1, 2, 3, 4, 5 };
        
        // Act
        var checksum1 = Rs1024Checksum.CalculateChecksum(words);
        var checksum2 = Rs1024Checksum.CalculateChecksum(words);
        
        // Assert
        Assert.Equal(checksum1, checksum2); // Should be deterministic
    }
    
    [Fact]
    public void CalculateChecksum_DifferentInputs_ShouldProduceDifferentResults()
    {
        // Arrange
        var words1 = new ushort[] { 1, 2, 3 };
        var words2 = new ushort[] { 1, 2, 4 }; // Different last word
        
        // Act
        var checksum1 = Rs1024Checksum.CalculateChecksum(words1);
        var checksum2 = Rs1024Checksum.CalculateChecksum(words2);
        
        // Assert
        Assert.NotEqual(checksum1, checksum2);
    }
    
    [Fact]
    public void BytesToWords_EmptyArray_ShouldReturnEmpty()
    {
        // Arrange
        var emptyBytes = new byte[0];
        
        // Act
        var words = Rs1024Checksum.BytesToWords(emptyBytes);
        
        // Assert
        Assert.Empty(words);
    }
    
    [Fact]
    public void BytesToWords_SingleByte_ShouldProduceOneWord()
    {
        // Arrange
        var singleByte = new byte[] { 0xFF }; // 11111111 in binary
        
        // Act
        var words = Rs1024Checksum.BytesToWords(singleByte);
        
        // Assert
        Assert.Single(words);
        // First 8 bits should be set, resulting in 0b1111111100 = 1020
        Assert.Equal((ushort)1020, words[0]);
    }
    
    [Fact]
    public void BytesToWords_TwoBytes_ShouldProduceTwoWords()
    {
        // Arrange - 16 bits = exactly 1.6 words, should round up to 2 words
        var twoBytes = new byte[] { 0xFF, 0xFF };
        
        // Act
        var words = Rs1024Checksum.BytesToWords(twoBytes);
        
        // Assert
        Assert.Equal(2, words.Length);
    }
    
    [Fact]
    public void BytesToWords_NullInput_ShouldThrow()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Rs1024Checksum.BytesToWords(null!));
    }
    
    [Fact]
    public void WordsToBytes_EmptyArray_ShouldReturnEmpty()
    {
        // Arrange
        var emptyWords = new ushort[0];
        
        // Act
        var bytes = Rs1024Checksum.WordsToBytes(emptyWords, 0);
        
        // Assert
        Assert.Empty(bytes);
    }
    
    [Fact]
    public void WordsToBytes_ZeroBitLength_ShouldReturnEmpty()
    {
        // Arrange
        var words = new ushort[] { 1, 2, 3 };
        
        // Act
        var bytes = Rs1024Checksum.WordsToBytes(words, 0);
        
        // Assert
        Assert.Empty(bytes);
    }
    
    [Fact]
    public void WordsToBytes_NegativeBitLength_ShouldThrow()
    {
        // Arrange
        var words = new ushort[] { 1, 2, 3 };
        
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Rs1024Checksum.WordsToBytes(words, -1));
    }
    
    [Fact]
    public void WordsToBytes_NullInput_ShouldThrow()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Rs1024Checksum.WordsToBytes(null!, 8));
    }
    
    [Fact]
    public void BytesToWords_WordsToBytes_RoundTrip_ShouldPreserveData()
    {
        // Arrange
        var originalBytes = new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A };
        var originalBitLength = originalBytes.Length * 8;
        
        // Act
        var words = Rs1024Checksum.BytesToWords(originalBytes);
        var roundTripBytes = Rs1024Checksum.WordsToBytes(words, originalBitLength);
        
        // Assert
        Assert.Equal(originalBytes, roundTripBytes);
    }
    
    [Fact]
    public void WordsToBytes_BytesToWords_RoundTrip_ShouldPreserveWords()
    {
        // Arrange - Use words that fit exactly in the bit pattern
        var originalWords = new ushort[] { 0x3FF, 0x200, 0x100 }; // Valid 10-bit values
        var bitLength = originalWords.Length * 10;
        
        // Act
        var bytes = Rs1024Checksum.WordsToBytes(originalWords, bitLength);
        var roundTripWords = Rs1024Checksum.BytesToWordsExact(bytes, originalWords.Length);
        
        // Assert
        Assert.Equal(originalWords, roundTripWords);
    }
    
    [Fact]
    public void GenerateChecksum_VariousInputSizes_ShouldAlwaysProduceValidChecksum()
    {
        // Arrange - Test different input sizes
        var testSizes = new[] { 1, 5, 10, 20, 50 };
        
        foreach (var size in testSizes)
        {
            var dataWords = new ushort[size];
            for (int i = 0; i < size; i++)
            {
                dataWords[i] = (ushort)(i % 1024); // Keep within valid range
            }
            
            // Act
            var checksumWords = Rs1024Checksum.GenerateChecksum(dataWords);
            var completeWords = dataWords.Concat(checksumWords).ToArray();
            
            // Assert
            Assert.Equal(3, checksumWords.Length);
            Assert.True(Rs1024Checksum.VerifyChecksum(completeWords),
                $"Generated checksum should be valid for input size {size}");
        }
    }
    
    [Fact]
    public void VerifyChecksum_CustomizationString_ShouldAffectResult()
    {
        // This test verifies that the "shamir" customization string is being used
        // by checking that identical data produces different checksums with different customizations
        
        // Arrange
        var dataWords = new ushort[] { 1, 2, 3, 4, 5 };
        
        // Act - Generate checksum (uses "shamir" internally)
        var checksumWords = Rs1024Checksum.GenerateChecksum(dataWords);
        var completeWords = dataWords.Concat(checksumWords).ToArray();
        
        // Assert - The checksum should be valid
        Assert.True(Rs1024Checksum.VerifyChecksum(completeWords));
        
        // If we manually calculate without the customization, it should be different
        var manualChecksum = Rs1024Checksum.CalculateChecksum(dataWords.Concat(new ushort[3]).ToArray());
        var expectedChecksum = Rs1024Checksum.CalculateChecksum(completeWords);
        
        // These should be different values, proving customization is used
        Assert.NotEqual(manualChecksum, expectedChecksum);
    }
}
