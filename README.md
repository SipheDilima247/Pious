# Pious

Pious is an installable, browser-based app for encrypting and decrypting text. Messages and passphrases are processed on your device; the app does not send them to a Pious server.

## Requirements

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
- A modern browser with Web Crypto support

## Run locally

From the repository root, restore dependencies and start the app:

```powershell
dotnet run --project .\Pious.App\Pious.App.csproj --urls http://localhost:5187
```

Open [http://localhost:5187](http://localhost:5187). Keep the terminal open while using the app; press **Ctrl+C** to stop it. Web Crypto requires a secure context, which includes `localhost`; deployed sites should use HTTPS.

## Use

1. Enter a passphrase of at least 12 characters, or generate a random key.
2. Select an algorithm and choose **Encrypt** or **Decrypt**.
3. Enter a message and select the action button. Copy the result using **Copy output**.
4. To decrypt, paste the complete encrypted output and use the same passphrase.

Pious generates a fresh random salt and nonce for each encryption. The output is a JSON envelope containing the ciphertext and the parameters needed to decrypt it. **Keep your passphrase safe**: it is not stored or recoverable by the app.

## Algorithms

- **AES** uses AES-GCM.
- **ChaCha20** uses ChaCha20-Poly1305.
- **Blowfish** and **Twofish** are compatibility options using CBC encryption with an HMAC-SHA-256 integrity check. Prefer AES or ChaCha20 for new messages.

Passphrases are processed with PBKDF2-HMAC-SHA-256. Do not lose the encrypted output or passphrase; Pious has no recovery service.

## Build and publish

Build the app:

```powershell
dotnet build .\Pious.App\Pious.App.csproj
```

Publish the static web app:

```powershell
dotnet publish .\Pious.App\Pious.App.csproj -c Release
```

Host the published `wwwroot` output over HTTPS. Pious is a Progressive Web App and can be installed from a compatible browser.
