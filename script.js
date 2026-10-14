"use strict";

const messageInput = document.getElementById("message");
const passphraseInput = document.getElementById("passphrase");
const resultInput = document.getElementById("result");
const statusMessage = document.getElementById("statusMessage");

const actionBtn = document.getElementById("actionBtn");
const actionText = document.getElementById("actionText");
const actionIcon = document.getElementById("actionIcon");

const encryptMode = document.getElementById("encryptMode");
const decryptMode = document.getElementById("decryptMode");

let currentMode = "encrypt";

const ITERATIONS = 600000;
const MAX_MESSAGE_LENGTH = 5000;
const MAX_PASSPHRASE_LENGTH = 256;
const MAGIC = "NTK3";
const VERSION = 1;

function setStatus(text, type = "") {
    statusMessage.textContent = text;
    statusMessage.className = type;
}

function setMode(mode) {
    currentMode = mode;

    const encrypting = mode === "encrypt";

    encryptMode.classList.toggle("active", encrypting);
    decryptMode.classList.toggle("active", !encrypting);

    actionText.textContent = encrypting
        ? "Encrypt Message"
        : "Decrypt Message";

    actionIcon.textContent = encrypting ? "♙" : "◉";

    messageInput.placeholder = encrypting
        ? "Write your message here..."
        : "Paste your NTk3 encrypted message here...";

    setStatus(encrypting
        ? "Ready to encrypt."
        : "Ready to decrypt.");

    statusMessage.className = "";
}

encryptMode.addEventListener("click", () => setMode("encrypt"));
decryptMode.addEventListener("click", () => setMode("decrypt"));

messageInput.addEventListener("input", () => {
    document.getElementById("charCount").textContent =
        `${messageInput.value.length} / ${MAX_MESSAGE_LENGTH}`;
});

document.getElementById("togglePassword").addEventListener("click", () => {
    const isPassword = passphraseInput.type === "password";

    passphraseInput.type = isPassword ? "text" : "password";

    document.getElementById("togglePassword").setAttribute(
        "aria-label",
        isPassword ? "Hide passphrase" : "Show passphrase"
    );
});

function toBase64(bytes) {
    let binary = "";

    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    return btoa(binary);
}

function fromBase64(text) {
    const binary = atob(text);

    return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function deriveKey(passphrase, salt) {
    const encoder = new TextEncoder();

    const material = await crypto.subtle.importKey(
        "raw",
        encoder.encode(passphrase),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: ITERATIONS,
            hash: "SHA-256"
        },
        material,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}

async function encryptMessage(plaintext, passphrase) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const key = await deriveKey(passphrase, salt);

    const header = `${MAGIC}.${VERSION}`;
    const encoder = new TextEncoder();

    const ciphertext = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv,
            additionalData: encoder.encode(header),
            tagLength: 128
        },
        key,
        encoder.encode(plaintext)
    );

    const payload = {
        magic: MAGIC,
        version: VERSION,
        iterations: ITERATIONS,
        salt: toBase64(salt),
        iv: toBase64(iv),
        ciphertext: toBase64(new Uint8Array(ciphertext))
    };

    return "NTK3:" + toBase64(
        encoder.encode(JSON.stringify(payload))
    );
}

async function decryptMessage(encoded, passphrase) {
    if (!encoded.startsWith("NTK3:")) {
        throw new Error("This is not a recognised NTk3 message.");
    }

    let payload;

    try {
        payload = JSON.parse(
            new TextDecoder().decode(
                fromBase64(encoded.slice(5))
            )
        );
    } catch {
        throw new Error("The encrypted message is malformed.");
    }

    if (
        payload.magic !== MAGIC ||
        payload.version !== VERSION ||
        payload.iterations !== ITERATIONS
    ) {
        throw new Error("Unsupported or invalid message format.");
    }

    const salt = fromBase64(payload.salt);
    const iv = fromBase64(payload.iv);
    const ciphertext = fromBase64(payload.ciphertext);

    if (
        salt.length !== 16 ||
        iv.length !== 12 ||
        ciphertext.length < 16 ||
        ciphertext.length > MAX_MESSAGE_LENGTH * 4 + 16
    ) {
        throw new Error("The encrypted message has invalid dimensions.");
    }

    const key = await deriveKey(passphrase, salt);
    const encoder = new TextEncoder();

    let plaintext;

    try {
        plaintext = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv,
                additionalData: encoder.encode(`${MAGIC}.${VERSION}`),
                tagLength: 128
            },
            key,
            ciphertext
        );
    } catch {
        throw new Error(
            "Decryption failed. Check the message and passphrase."
        );
    }

    return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
}

actionBtn.addEventListener("click", async () => {
    const message = messageInput.value;
    const passphrase = passphraseInput.value;

    if (!window.isSecureContext || !crypto.subtle) {
        setStatus(
            "Secure encryption is unavailable. Open NTk3 on localhost or an HTTPS website.",
            "error"
        );
        return;
    }

    if (!message.trim()) {
        setStatus("Please enter a message first.", "error");
        messageInput.focus();
        return;
    }

    if (message.length > MAX_MESSAGE_LENGTH) {
        setStatus("Your message exceeds the 5000-character limit.", "error");
        return;
    }

    if (!passphrase.trim()) {
        setStatus("Please enter your secret passphrase.", "error");
        passphraseInput.focus();
        return;
    }

    if (passphrase.length > MAX_PASSPHRASE_LENGTH) {
        setStatus("Your passphrase is too long.", "error");
        return;
    }

    actionBtn.disabled = true;
    actionText.textContent = currentMode === "encrypt"
        ? "Encrypting..."
        : "Decrypting...";

    setStatus("Processing locally in your browser...");

    try {
        let output;

        if (currentMode === "encrypt") {
            output = await encryptMessage(message, passphrase);
        } else {
            output = await decryptMessage(message.trim(), passphrase);
        }

        resultInput.value = output;
        setStatus(
            currentMode === "encrypt"
                ? "Message encrypted successfully."
                : "Message decrypted successfully.",
            "success"
        );
    } catch (error) {
        setStatus(
            error instanceof Error
                ? error.message
                : "Something went wrong.",
            "error"
        );
    } finally {
        actionBtn.disabled = false;
        actionText.textContent = currentMode === "encrypt"
            ? "Encrypt Message"
            : "Decrypt Message";
    }
});

document.getElementById("copyBtn").addEventListener("click", async () => {
    if (!resultInput.value) {
        setStatus("There is no result to copy.", "error");
        return;
    }

    try {
        await navigator.clipboard.writeText(resultInput.value);
        setStatus("Copied to clipboard.", "success");
    } catch {
        resultInput.focus();
        resultInput.select();

        const copied = document.execCommand("copy");

        setStatus(
            copied
                ? "Copied to clipboard."
                : "Select the result and copy it manually.",
            copied ? "success" : "error"
        );
    }
});

document.getElementById("clearBtn").addEventListener("click", () => {
    messageInput.value = "";
    resultInput.value = "";
    passphraseInput.value = "";

    document.getElementById("charCount").textContent = "0 / 5000";

    setStatus("Fields cleared.");
    messageInput.focus();
});

document.getElementById("themeBtn").addEventListener("click", () => {
    document.body.classList.toggle("light");

    const isLight = document.body.classList.contains("light");

    document.getElementById("themeBtn").textContent = isLight ? "☾" : "☼";
    document.querySelector('meta[name="theme-color"]').content =
        isLight ? "#f3f6ff" : "#080b12";
});



// NTk3 — Supabase configuration
const SUPABASE_URL = "https://ijmgnajbswmujtkrtfnb.supabase.co";
const SUPABASE_PUBLISHABLE_KEY = "sb_publishable_Et7wT2yGdkqzPTLJPjc2Bw_CCFQtKyv";

const supabaseClient = window.supabase.createClient(
    SUPABASE_URL,
    SUPABASE_PUBLISHABLE_KEY
);

// NTk3 Authentication

const authEmail = document.getElementById("authEmail");
const authPassword = document.getElementById("authPassword");
const authStatus = document.getElementById("authStatus");
const authPanel = document.getElementById("authPanel");

document.getElementById("signUpBtn").addEventListener("click", async () => {
    const email = authEmail.value.trim();
    const password = authPassword.value;

    if (!email || !password) {
        authStatus.textContent = "Enter your email and password.";
        return;
    }

    if (password.length < 12) {
        authStatus.textContent =
            "Use a password of at least 12 characters.";
        return;
    }

    authStatus.textContent = "Creating your account...";

    try {
        const { data, error } = await supabaseClient.auth.signUp({
            email,
            password
        });

        if (error) throw error;

        authStatus.textContent = data.session
            ? "Account created. You're signed in!"
            : "Account created. Check your email to confirm registration.";
    } catch (error) {
        authStatus.textContent = error.message;
    }
});

document.getElementById("signInBtn").addEventListener("click", async () => {
    const email = authEmail.value.trim();
    const password = authPassword.value;

    if (!email || !password) {
        authStatus.textContent = "Enter your email and password.";
        return;
    }

    authStatus.textContent = "Signing in...";

    try {
        const { data, error } = await supabaseClient.auth.signInWithPassword({
            email,
            password
        });

        if (error) throw error;

        authStatus.textContent = "Signed in successfully!";
        console.log("NTk3 authentication successful.");
    } catch (error) {
        authStatus.textContent = error.message;
    }
});

// NTk3 — Authentication diagnostics and button handlers

(() => {
    const signInButton = document.getElementById("signInBtn");
    const signUpButton = document.getElementById("signUpBtn");
    const emailInput = document.getElementById("authEmail");
    const passwordInput = document.getElementById("authPassword");
    const status = document.getElementById("authStatus");

    if (!signInButton || !signUpButton || !emailInput ||
        !passwordInput || !status) {
        console.error("NTk3: Authentication elements are missing.");
        return;
    }

    if (typeof supabaseClient === "undefined") {
        status.textContent = "Connection error: Supabase is not configured.";
        console.error("NTk3: supabaseClient is not defined.");
        return;
    }

    async function authenticate(mode) {
        const email = emailInput.value.trim();
        const password = passwordInput.value;

        if (!email || !password) {
            status.textContent = "Please enter your email and password.";
            return;
        }

        status.textContent = mode === "signin"
            ? "Signing in..."
            : "Creating your account...";

        signInButton.disabled = true;
        signUpButton.disabled = true;

        try {
            const result = mode === "signin"
                ? await supabaseClient.auth.signInWithPassword({
                    email,
                    password
                })
                : await supabaseClient.auth.signUp({
                    email,
                    password
                });

            if (result.error) throw result.error;

            status.textContent = mode === "signin"
                ? "Signed in successfully!"
                : result.data.session
                    ? "Account created successfully!"
                    : "Check your email to confirm your account.";

            console.log("NTk3 authentication response:", {
                mode,
                success: !result.error,
                hasSession: Boolean(result.data.session)
            });

        } catch (error) {
            status.textContent = error.message || "Authentication failed.";
            console.error("NTk3 authentication error:", error);
        } finally {
            signInButton.disabled = false;
            signUpButton.disabled = false;
        }
    }

    signInButton.addEventListener("click", () => authenticate("signin"));
    signUpButton.addEventListener("click", () => authenticate("signup"));

    console.log("NTk3: Authentication buttons connected.");
})();