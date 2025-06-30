using System;
using System.Linq;
using System.Text.Json;
using Slip39.Core;
using Xunit;

namespace Slip39.Core.Tests;

/// <summary>
/// Unit tests for the Slip39ShareParser class.
/// Tests parsing functionality for mnemonic words, hexadecimal strings, and JSON.
/// </summary>
public class Slip39ShareParserTests
{
    private readonly Slip39Share _testShare;
    private readonly string _testHex;
    private readonly string _testJson;

    public Slip39ShareParserTests()
    {
        // Create a test share with known values
        _testShare = new Slip39Share(
            identifier: 12345,
            isExtendable: false,
            iterationExponent: 1,
            groupIndex: 0,
            groupThreshold: 1,
            groupCount: 1,
            memberIndex: 0,
            memberThreshold: 2,
            shareValue: new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 },
            checksum: 123456789
        );

        // Generate test hex from the share
        _testHex = _testShare.ToHex();

        // Generate test JSON from the share
        _testJson = Slip39ShareParser.ToJson(_testShare);
    }

    #region Hex Parsing Tests




    [Fact]
    public void ParseFromHex_EmptyString_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromHex(""));
    }

    [Fact]
    public void ParseFromHex_NullString_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromHex(null));
    }

    [Fact]
    public void ParseFromHex_OddLengthHex_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromHex("12345"));
    }

    [Fact]
    public void ParseFromHex_InvalidHexCharacters_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromHex("123G"));
    }

    #endregion

    #region JSON Parsing Tests

    [Fact]
    public void ParseFromJson_ValidJson_ReturnsCorrectShare()
    {
        // Act
        var parsedShare = Slip39ShareParser.ParseFromJson(_testJson);

        // Assert
        Assert.Equal(_testShare.Identifier, parsedShare.Identifier);
        Assert.Equal(_testShare.IsExtendable, parsedShare.IsExtendable);
        Assert.Equal(_testShare.IterationExponent, parsedShare.IterationExponent);
        Assert.Equal(_testShare.GroupIndex, parsedShare.GroupIndex);
        Assert.Equal(_testShare.GroupThreshold, parsedShare.GroupThreshold);
        Assert.Equal(_testShare.GroupCount, parsedShare.GroupCount);
        Assert.Equal(_testShare.MemberIndex, parsedShare.MemberIndex);
        Assert.Equal(_testShare.MemberThreshold, parsedShare.MemberThreshold);
        Assert.Equal(_testShare.ShareValue, parsedShare.ShareValue);
        Assert.Equal(_testShare.Checksum, parsedShare.Checksum);
    }

    [Fact]
    public void ToJson_ValidShare_ReturnsValidJson()
    {
        // Act
        var json = Slip39ShareParser.ToJson(_testShare);

        // Assert
        Assert.NotNull(json);
        Assert.Contains("identifier", json);
        Assert.Contains("extendable", json);
        Assert.Contains("shareValue", json);

        // Verify it can be parsed back
        var reparsed = Slip39ShareParser.ParseFromJson(json);
        Assert.Equal(_testShare.Identifier, reparsed.Identifier);
    }

    [Fact]
    public void ToJson_WithIndentation_ReturnsFormattedJson()
    {
        // Act
        var json = Slip39ShareParser.ToJson(_testShare, indented: true);

        // Assert
        Assert.True(json.Contains("\n") || json.Contains("\r"));
    }

    [Fact]
    public void ToJson_WithoutIndentation_ReturnsCompactJson()
    {
        // Act
        var json = Slip39ShareParser.ToJson(_testShare, indented: false);

        // Assert
        Assert.DoesNotContain("\n", json);
        Assert.DoesNotContain("\r", json);
    }

    [Fact]
    public void ParseFromJson_EmptyString_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromJson(""));
    }

    [Fact]
    public void ParseFromJson_NullString_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromJson(null));
    }

    [Fact]
    public void ParseFromJson_InvalidJson_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromJson("{ invalid json }"));
    }

    [Fact]
    public void ToJson_NullShare_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Slip39ShareParser.ToJson(null));
    }

    #endregion

    #region Mnemonic Parsing Tests

    [Fact]
    public void ParseFromMnemonic_ValidMnemonic20Words_ParsesSuccessfully()
    {
        // Arrange - Use a valid 20-word SLIP-39 test vector mnemonic
        var mnemonic = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard";

        // Act & Assert - Should not throw
        var result = Slip39ShareParser.ParseFromMnemonic(mnemonic);
        Assert.NotNull(result);
    }


    [Fact]
    public void ParseFromMnemonicWords_ValidWordArray_ParsesSuccessfully()
    {
        // Arrange - Use real SLIP-39 words
        var words = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard".Split(' ');

        // Act
        var result = Slip39ShareParser.ParseFromMnemonicWords(words);

        // Assert
        Assert.NotNull(result);
    }

    [Fact]
    public void ParseFromMnemonic_InvalidWordCount_ThrowsArgumentException()
    {
        // Arrange - Invalid word count
        var mnemonic = "word1 word2 word3";

        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromMnemonic(mnemonic));
    }

    [Fact]
    public void ParseFromMnemonic_EmptyString_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromMnemonic(""));
    }

    [Fact]
    public void ParseFromMnemonic_NullString_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Slip39ShareParser.ParseFromMnemonic(null));
    }

    [Fact]
    public void ParseFromMnemonicWords_NullArray_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Slip39ShareParser.ParseFromMnemonicWords(null));
    }

    #endregion

    #region Validation Tests

    [Fact]
    public void ValidateShare_ValidShare_ReturnsTrue()
    {
        // Act
        var isValid = Slip39ShareParser.ValidateShare(_testShare);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void ValidateShare_NullShare_ReturnsFalse()
    {
        // Act
        var isValid = Slip39ShareParser.ValidateShare(null);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void ValidateShare_InvalidIdentifier_ThrowsException()
    {
        // Act & Assert - Constructor should throw for invalid identifier
        Assert.Throws<ArgumentOutOfRangeException>(() => new Slip39Share(
            identifier: 0x8000, // 16 bits, should be max 15
            isExtendable: false,
            iterationExponent: 1,
            groupIndex: 0,
            groupThreshold: 1,
            groupCount: 1,
            memberIndex: 0,
            memberThreshold: 2,
            shareValue: new byte[] { 0x01, 0x02 },
            checksum: 123
        ));
    }

    [Fact]
    public void ValidateShare_InvalidIterationExponent_ThrowsException()
    {
        // Act & Assert - Constructor should throw for invalid iteration exponent
        Assert.Throws<ArgumentOutOfRangeException>(() => new Slip39Share(
            identifier: 123,
            isExtendable: false,
            iterationExponent: 16, // > 4 bits
            groupIndex: 0,
            groupThreshold: 1,
            groupCount: 1,
            memberIndex: 0,
            memberThreshold: 2,
            shareValue: new byte[] { 0x01, 0x02 },
            checksum: 123
        ));
    }

    [Fact]
    public void ValidateShare_InvalidChecksum_ThrowsException()
    {
        // Act & Assert - Constructor should throw for invalid checksum
        Assert.Throws<ArgumentOutOfRangeException>(() => new Slip39Share(
            identifier: 123,
            isExtendable: false,
            iterationExponent: 1,
            groupIndex: 0,
            groupThreshold: 1,
            groupCount: 1,
            memberIndex: 0,
            memberThreshold: 2,
            shareValue: new byte[] { 0x01, 0x02 },
            checksum: 0x40000000 // > 30 bits
        ));
    }

    #endregion

    #region Round-trip Tests


    [Fact]
    public void RoundTrip_JsonToShareToJson_PreservesData()
    {
        // Act
        var parsedShare = Slip39ShareParser.ParseFromJson(_testJson);
        var regeneratedJson = Slip39ShareParser.ToJson(parsedShare);

        // Parse both JSON strings to compare values (since formatting might differ)
        var originalData = JsonSerializer.Deserialize<JsonElement>(_testJson);
        var regeneratedData = JsonSerializer.Deserialize<JsonElement>(regeneratedJson);

        // Assert key fields are equal
        Assert.Equal(originalData.GetProperty("identifier").GetUInt16(), 
                       regeneratedData.GetProperty("identifier").GetUInt16());
        Assert.Equal(originalData.GetProperty("extendable").GetBoolean(), 
                       regeneratedData.GetProperty("extendable").GetBoolean());
    }

    #endregion

    #region Edge Cases


    [Fact]
    public void ParseFromMnemonic_ExtraWhitespace_HandlesGracefully()
    {
        // Arrange - Use real SLIP-39 words with extra whitespace
        var words = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard".Split(' ');
        var mnemonicWithExtraSpaces = "  " + string.Join("   ", words) + "  ";

        // Act
        var result = Slip39ShareParser.ParseFromMnemonic(mnemonicWithExtraSpaces);

        // Assert
        Assert.NotNull(result);
    }

    #endregion
}
