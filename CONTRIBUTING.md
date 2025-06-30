# Contributing to SLIP-0039 .NET

Thank you for your interest in contributing to the SLIP-0039 .NET implementation! This document provides guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you are expected to uphold our code of conduct:
- Be respectful and inclusive
- Focus on constructive feedback
- Help create a welcoming environment for all contributors

## How to Contribute

### Reporting Issues

1. **Search existing issues** first to avoid duplicates
2. **Use clear, descriptive titles** for new issues
3. **Provide detailed information** including:
   - .NET version and operating system
   - Steps to reproduce the issue
   - Expected vs. actual behavior
   - Any error messages or logs

### Submitting Pull Requests

1. **Fork the repository** and create a feature branch
2. **Follow coding standards** described below
3. **Write or update tests** for your changes
4. **Ensure all tests pass** before submitting
5. **Update documentation** if needed
6. **Submit a pull request** with a clear description

## Development Setup

### Prerequisites
- .NET 9.0 SDK or later
- Git
- Your preferred IDE (Visual Studio, VS Code, Rider, etc.)

### Getting Started
```bash
# Clone your fork
git clone https://github.com/yourusername/Slip39DotNet.git
cd Slip39DotNet

# Build the solution
dotnet build

# Run tests
dotnet test

# Run CLI tool
dotnet run --project Slip39.Console -- --help
```

## Coding Standards

### C# Guidelines
Follow the established patterns in the codebase:

```csharp
// Use meaningful names
public class Slip39ShareValidator
{
    private readonly IWordlistProvider _wordlistProvider;
    
    // Document public APIs
    /// <summary>
    /// Validates a SLIP-0039 mnemonic share for correctness
    /// </summary>
    /// <param name="mnemonic">The mnemonic string to validate</param>
    /// <returns>True if valid, false otherwise</returns>
    public bool ValidateMnemonic(string mnemonic)
    {
        // Implementation
    }
}
```

### Project Structure
- **Slip39.Core**: Core cryptographic implementations
- **Slip39.Console**: CLI application  
- **Slip39.Core.Tests**: Comprehensive test suite

### Key Principles
1. **Security First**: Handle cryptographic material securely
2. **SLIP-0039 Compliance**: Follow the specification exactly
3. **Performance**: Efficient algorithms and memory usage
4. **Testability**: Write testable, modular code
5. **Documentation**: Document public APIs and complex logic

## Testing Guidelines

### Test Requirements
- **Unit tests** for all public APIs
- **Integration tests** for CLI commands
- **Reference vector tests** using official SLIP-0039 test vectors
- **Error condition tests** for edge cases and invalid inputs

### Writing Tests
```csharp
[Fact]
public void GenerateShares_ValidInput_ReturnsCorrectShares()
{
    // Arrange
    var secret = Encoding.UTF8.GetBytes("test secret");
    var threshold = 2;
    var shareCount = 3;
    
    // Act
    var shares = Slip39ShareGeneration.GenerateShares(secret, threshold, shareCount);
    
    // Assert
    Assert.Equal(shareCount, shares.Count);
    Assert.All(shares, share => Assert.True(share.IsValid()));
}
```

### Running Tests
```bash
# Run all tests
dotnet test

# Run with coverage
dotnet test --collect:"XPlat Code Coverage"

# Run specific test class
dotnet test --filter "ClassName=Slip39ShareGenerationTests"
```

## Documentation

### Code Documentation
- Use XML documentation comments for all public APIs
- Include parameter descriptions and return value information
- Provide usage examples for complex APIs

### README Updates
- Update relevant README files when adding features
- Include usage examples for new CLI commands
- Update the feature list when appropriate

## Security Considerations

### Cryptographic Code
- **Never** implement custom cryptographic primitives
- Follow established security practices
- Clear sensitive data from memory when possible
- Validate all inputs rigorously

### Test Data
- Use only test vectors from the official specification
- Never commit real private keys or secrets
- Use clearly marked test data in examples

## Pull Request Process

### Before Submitting
1. **Rebase** your branch on the latest main
2. **Run all tests** and ensure they pass
3. **Check code formatting** and style
4. **Update documentation** as needed
5. **Write clear commit messages**

### PR Description Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Other (please describe)

## Testing
- [ ] All existing tests pass
- [ ] New tests added for changes
- [ ] Manual testing completed

## Documentation
- [ ] Code comments updated
- [ ] README updated (if needed)
- [ ] API documentation updated

## Security Impact
Describe any security implications of the changes
```

### Review Process
1. **Automated checks** must pass (build, tests)
2. **Code review** by project maintainers
3. **Security review** for cryptographic changes
4. **Documentation review** for user-facing changes

## Release Process

### Versioning
We follow [Semantic Versioning](https://semver.org/):
- **Major**: Breaking changes
- **Minor**: New features (backward compatible)
- **Patch**: Bug fixes (backward compatible)

### Release Checklist
- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version numbers updated
- [ ] Security review completed

## Getting Help

### Communication Channels
- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and general discussion
- **Pull Request Comments**: For code-specific questions

### Resources
- [SLIP-0039 Specification](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
- [BIP32 Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [.NET Coding Conventions](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/inside-a-program/coding-conventions)

## License

By contributing to this project, you agree that your contributions will be licensed under the MIT License.
