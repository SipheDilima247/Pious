using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.JSInterop;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Digests;

namespace Pious.App.Services;

public sealed class MessageCryptography(IJSRuntime jsRuntime)
{
    private const int Iterations = 600_000;
    private const int MaximumInputLength = 1_000_000;
    private const string KdfName = "PBKDF2-SHA256";
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public async Task<string> EncryptAsync(string plaintext, string passphrase, string algorithm)
    {
        ValidateInput(plaintext, passphrase);
        ValidateAlgorithm(algorithm);

        var salt = RandomNumberGenerator.GetBytes(16);
        var nonce = RandomNumberGenerator.GetBytes(GetNonceLength(algorithm));
        var header = CreateHeader(algorithm, salt, nonce);
        var keys = await DeriveKeysAsync(passphrase, salt);

        try
        {
            var input = Encoding.UTF8.GetBytes(plaintext);
            byte[] ciphertext;
            string? authenticationTag = null;

            if (IsAuthenticatedCipher(algorithm))
            {
                ciphertext = TransformAuthenticated(true, algorithm, keys[..32], nonce, header, input);
            }
            else
            {
                ciphertext = TransformLegacy(true, algorithm, keys[..32], nonce, input);
                authenticationTag = ComputeMac(keys[32..], header, ciphertext);
            }

            var envelope = new CipherEnvelope(
                1,
                algorithm,
                KdfName,
                Iterations,
                Convert.ToBase64String(salt),
                Convert.ToBase64String(nonce),
                Convert.ToBase64String(ciphertext),
                authenticationTag);

            return JsonSerializer.Serialize(envelope, JsonOptions);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keys);
        }
    }

    public async Task<string> DecryptAsync(string serializedEnvelope, string passphrase)
    {
        if (string.IsNullOrWhiteSpace(serializedEnvelope) || serializedEnvelope.Length > MaximumInputLength)
        {
            throw new ArgumentException("Enter a valid Pious encrypted message.");
        }

        if (string.IsNullOrWhiteSpace(passphrase) || passphrase.Length < 12)
        {
            throw new ArgumentException("Enter the passphrase used to encrypt this message (at least 12 characters).");
        }

        CipherEnvelope? envelope;
        try
        {
            envelope = JsonSerializer.Deserialize<CipherEnvelope>(serializedEnvelope, JsonOptions);
        }
        catch (JsonException)
        {
            throw new CryptographicException("This is not a valid Pious encrypted message.");
        }

        if (envelope is null ||
            envelope.Version != 1 ||
            envelope.Iterations != Iterations ||
            envelope.Kdf != KdfName)
        {
            throw new CryptographicException("This encrypted message uses an unsupported format.");
        }

        ValidateAlgorithm(envelope.Algorithm);

        byte[] salt;
        byte[] nonce;
        byte[] ciphertext;
        byte[]? authenticationTag;
        try
        {
            salt = Convert.FromBase64String(envelope.Salt);
            nonce = Convert.FromBase64String(envelope.Nonce);
            ciphertext = Convert.FromBase64String(envelope.Ciphertext);
            authenticationTag = envelope.AuthenticationTag is null
                ? null
                : Convert.FromBase64String(envelope.AuthenticationTag);
        }
        catch (FormatException)
        {
            throw new CryptographicException("This encrypted message has invalid encoding.");
        }

        if (salt.Length != 16 || nonce.Length != GetNonceLength(envelope.Algorithm) ||
            ciphertext.Length > MaximumInputLength || (!IsAuthenticatedCipher(envelope.Algorithm) && authenticationTag?.Length != 32))
        {
            throw new CryptographicException("This encrypted message has invalid parameters.");
        }

        var header = CreateHeader(envelope.Algorithm, salt, nonce);
        var keys = await DeriveKeysAsync(passphrase, salt);
        try
        {
            byte[] plaintext;
            if (IsAuthenticatedCipher(envelope.Algorithm))
            {
                if (authenticationTag is not null)
                {
                    throw new CryptographicException("This encrypted message has invalid parameters.");
                }

                plaintext = TransformAuthenticated(false, envelope.Algorithm, keys[..32], nonce, header, ciphertext);
            }
            else
            {
                var expectedTag = ComputeMacBytes(keys[32..], header, ciphertext);
                if (!CryptographicOperations.FixedTimeEquals(expectedTag, authenticationTag!))
                {
                    throw new CryptographicException("The passphrase is incorrect or the encrypted message was changed.");
                }

                plaintext = TransformLegacy(false, envelope.Algorithm, keys[..32], nonce, ciphertext);
            }

            try
            {
                return StrictUtf8.GetString(plaintext);
            }
            catch (DecoderFallbackException)
            {
                throw new CryptographicException("The decrypted data is not valid UTF-8 text.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        catch (InvalidCipherTextException)
        {
            throw new CryptographicException("The passphrase is incorrect or the encrypted message was changed.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keys);
        }
    }

    private async Task<byte[]> DeriveKeysAsync(string passphrase, byte[] salt)
    {
        var derivedKey = await jsRuntime.InvokeAsync<string>(
            "piousCrypto.deriveKey",
            passphrase,
            Convert.ToBase64String(salt),
            Iterations,
            64);

        try
        {
            return Convert.FromBase64String(derivedKey);
        }
        catch (FormatException)
        {
            throw new CryptographicException("The browser could not derive an encryption key.");
        }
    }

    private static byte[] TransformAuthenticated(
        bool encrypt,
        string algorithm,
        byte[] key,
        byte[] nonce,
        byte[] associatedData,
        byte[] input)
    {
        IAeadCipher cipher = algorithm switch
        {
            "AES" => new GcmBlockCipher(new AesEngine()),
            "ChaCha20" => new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305(),
            _ => throw new CryptographicException("Unsupported authenticated cipher.")
        };
        cipher.Init(encrypt, new AeadParameters(new KeyParameter(key), 128, nonce, associatedData));

        var output = new byte[cipher.GetOutputSize(input.Length)];
        var length = cipher.ProcessBytes(input, 0, input.Length, output, 0);
        length += cipher.DoFinal(output, length);
        return output[..length];
    }

    private static byte[] TransformLegacy(bool encrypt, string algorithm, byte[] key, byte[] iv, byte[] input)
    {
        IBlockCipher engine = algorithm switch
        {
            "Blowfish" => new BlowfishEngine(),
            "Twofish" => new TwofishEngine(),
            _ => throw new CryptographicException("Unsupported compatibility cipher.")
        };
        var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(engine), new Pkcs7Padding());
        cipher.Init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));

        var output = new byte[cipher.GetOutputSize(input.Length)];
        var length = cipher.ProcessBytes(input, 0, input.Length, output, 0);
        length += cipher.DoFinal(output, length);
        return output[..length];
    }

    private static string ComputeMac(byte[] key, byte[] header, byte[] ciphertext) =>
        Convert.ToBase64String(ComputeMacBytes(key, header, ciphertext));

    private static byte[] ComputeMacBytes(byte[] key, byte[] header, byte[] ciphertext)
    {
        var mac = new HMac(new Sha256Digest());
        mac.Init(new KeyParameter(key));
        mac.BlockUpdate(header, 0, header.Length);
        mac.BlockUpdate(ciphertext, 0, ciphertext.Length);
        var output = new byte[mac.GetMacSize()];
        mac.DoFinal(output, 0);
        return output;
    }

    private static byte[] CreateHeader(string algorithm, byte[] salt, byte[] nonce) =>
        Encoding.UTF8.GetBytes(string.Join(
            '|',
            "Pious",
            "1",
            algorithm,
            KdfName,
            Iterations.ToString(System.Globalization.CultureInfo.InvariantCulture),
            Convert.ToBase64String(salt),
            Convert.ToBase64String(nonce)));

    private static bool IsAuthenticatedCipher(string algorithm) => algorithm is "AES" or "ChaCha20";

    private static int GetNonceLength(string algorithm) => algorithm switch
    {
        "AES" or "ChaCha20" => 12,
        "Twofish" => 16,
        "Blowfish" => 8,
        _ => throw new CryptographicException("Unsupported cipher.")
    };

    private static void ValidateAlgorithm(string algorithm)
    {
        if (algorithm is not ("AES" or "ChaCha20" or "Blowfish" or "Twofish"))
        {
            throw new ArgumentException("Select a supported encryption algorithm.");
        }
    }

    private static void ValidateInput(string plaintext, string passphrase)
    {
        if (string.IsNullOrEmpty(plaintext) || plaintext.Length > MaximumInputLength)
        {
            throw new ArgumentException("Enter a message of up to 1,000,000 characters.");
        }

        if (string.IsNullOrWhiteSpace(passphrase) || passphrase.Length < 12)
        {
            throw new ArgumentException("Use a passphrase with at least 12 characters.");
        }
    }

    private sealed record CipherEnvelope(
        int Version,
        string Algorithm,
        string Kdf,
        int Iterations,
        string Salt,
        string Nonce,
        string Ciphertext,
        string? AuthenticationTag);
}
