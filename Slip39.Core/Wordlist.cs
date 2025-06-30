using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

namespace Slip39.Core
{
    /// <summary>
    /// SLIP-0039 wordlist containing 1024 words for mnemonic generation and validation.
    /// Each word is mapped to an index from 0 to 1023.
    /// </summary>
    public static class Wordlist
    {
        private static readonly Lazy<string[]> _words = new Lazy<string[]>(LoadWords);
        private static readonly Lazy<Dictionary<string, int>> _wordToIndex = new Lazy<Dictionary<string, int>>(CreateWordToIndexMap);

        /// <summary>
        /// Gets the array of all 1024 words in the SLIP-0039 wordlist.
        /// </summary>
        public static string[] Words => _words.Value;

        /// <summary>
        /// Gets the total number of words in the wordlist.
        /// </summary>
        public static int WordCount => 1024;

        /// <summary>
        /// Gets the word at the specified index.
        /// </summary>
        /// <param name="index">The index of the word (0-1023).</param>
        /// <returns>The word at the specified index.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when index is not between 0 and 1023.</exception>
        public static string GetWord(int index)
        {
            if (index < 0 || index >= WordCount)
            {
                throw new ArgumentOutOfRangeException(nameof(index), 
                    $"Index must be between 0 and {WordCount - 1}.");
            }

            return Words[index];
        }

        /// <summary>
        /// Gets the index of the specified word.
        /// </summary>
        /// <param name="word">The word to find the index for.</param>
        /// <returns>The index of the word (0-1023).</returns>
        /// <exception cref="ArgumentException">Thrown when the word is not found in the wordlist.</exception>
        public static int GetIndex(string word)
        {
            if (string.IsNullOrWhiteSpace(word))
            {
                throw new ArgumentException("Word cannot be null or empty.", nameof(word));
            }

            if (_wordToIndex.Value.TryGetValue(word.ToLowerInvariant(), out int index))
            {
                return index;
            }

            throw new ArgumentException($"Word '{word}' not found in wordlist.", nameof(word));
        }

        /// <summary>
        /// Checks if the specified word exists in the wordlist.
        /// </summary>
        /// <param name="word">The word to check.</param>
        /// <returns>True if the word exists in the wordlist; otherwise, false.</returns>
        public static bool ContainsWord(string word)
        {
            if (string.IsNullOrWhiteSpace(word))
            {
                return false;
            }

            return _wordToIndex.Value.ContainsKey(word.ToLowerInvariant());
        }

        /// <summary>
        /// Validates that all words in the provided collection exist in the wordlist.
        /// </summary>
        /// <param name="words">The words to validate.</param>
        /// <returns>True if all words are valid; otherwise, false.</returns>
        public static bool ValidateWords(IEnumerable<string> words)
        {
            if (words == null)
            {
                return false;
            }

            return words.All(ContainsWord);
        }

        /// <summary>
        /// Converts a collection of words to their corresponding indices.
        /// </summary>
        /// <param name="words">The words to convert.</param>
        /// <returns>An array of indices corresponding to the words.</returns>
        /// <exception cref="ArgumentException">Thrown when any word is not found in the wordlist.</exception>
        public static int[] WordsToIndices(IEnumerable<string> words)
        {
            if (words == null)
            {
                throw new ArgumentNullException(nameof(words));
            }

            return words.Select(GetIndex).ToArray();
        }

        /// <summary>
        /// Converts a collection of indices to their corresponding words.
        /// </summary>
        /// <param name="indices">The indices to convert.</param>
        /// <returns>An array of words corresponding to the indices.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when any index is not between 0 and 1023.</exception>
        public static string[] IndicesToWords(IEnumerable<int> indices)
        {
            if (indices == null)
            {
                throw new ArgumentNullException(nameof(indices));
            }

            return indices.Select(GetWord).ToArray();
        }

        private static string[] LoadWords()
        {
            var assembly = Assembly.GetExecutingAssembly();
            var resourceName = "Slip39.Core.wordlist.txt";
            
            // Try to load from embedded resource first
            using (var stream = assembly.GetManifestResourceStream(resourceName))
            {
                if (stream != null)
                {
                    return LoadWordsFromStream(stream);
                }
            }
            
            // Fallback to file system
            var assemblyLocation = assembly.Location;
            var assemblyDirectory = Path.GetDirectoryName(assemblyLocation);
            var wordlistPath = Path.Combine(assemblyDirectory, "wordlist.txt");
            
            if (File.Exists(wordlistPath))
            {
                return LoadWordsFromFile(wordlistPath);
            }
            
            throw new FileNotFoundException("Wordlist file not found. Expected embedded resource or file at: " + wordlistPath);
        }

        private static string[] LoadWordsFromStream(Stream stream)
        {
            var wordsList = new List<string>();
            using (var reader = new StreamReader(stream))
            {
                string line;
                
                while ((line = reader.ReadLine()) != null)
                {
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        continue;
                    }
                    
                    // Try to parse as "index|word" format first
                    var parts = line.Split('|');
                    if (parts.Length == 2 && int.TryParse(parts[0], out int index) && index >= 1 && index <= WordCount)
                    {
                        // Ensure we have enough space in the list
                        while (wordsList.Count < index)
                        {
                            wordsList.Add("");
                        }
                        if (wordsList.Count == index)
                        {
                            wordsList.Add(parts[1].Trim().ToLowerInvariant());
                        }
                        else
                        {
                            wordsList[index - 1] = parts[1].Trim().ToLowerInvariant();
                        }
                    }
                    else
                    {
                        // Assume simple word list format (one word per line)
                        var word = line.Trim().ToLowerInvariant();
                        if (!string.IsNullOrEmpty(word))
                        {
                            wordsList.Add(word);
                        }
                    }
                }
                
                if (wordsList.Count != WordCount)
                {
                    throw new InvalidDataException($"Expected {WordCount} words but found {wordsList.Count}.");
                }
            }
            
            return wordsList.ToArray();
        }

        private static string[] LoadWordsFromFile(string filePath)
        {
            using (var stream = File.OpenRead(filePath))
            {
                return LoadWordsFromStream(stream);
            }
        }

        private static Dictionary<string, int> CreateWordToIndexMap()
        {
            var map = new Dictionary<string, int>(WordCount);
            var words = Words;
            
            for (int i = 0; i < words.Length; i++)
            {
                if (!string.IsNullOrEmpty(words[i]))
                {
                    map[words[i]] = i;
                }
            }
            
            return map;
        }
    }
}
