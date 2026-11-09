window.piousCrypto = {
    async deriveKey(passphrase, saltBase64, iterations, length) {
        if (!globalThis.crypto?.subtle) {
            throw new Error("Web Crypto is unavailable. Use a secure browser context (HTTPS or localhost).");
        }

        const salt = Uint8Array.from(atob(saltBase64), character => character.charCodeAt(0));
        const material = await crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(passphrase),
            "PBKDF2",
            false,
            ["deriveBits"]);
        const key = await crypto.subtle.deriveBits(
            { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
            material,
            length * 8);

        return btoa(String.fromCharCode(...new Uint8Array(key)));
    },

    async copyText(text) {
        await navigator.clipboard.writeText(text);
    },

    async pasteText() {
        return await navigator.clipboard.readText();
    }
};
