"use strict";

// NTk3 configuration: browser-safe Supabase publishable key only.
const SUPABASE_URL = "https://ijmgnajbswmujtkrtfnb.supabase.co";
const SUPABASE_PUBLISHABLE_KEY = "sb_publishable_Et7wT2yGdkqzPTLJPjc2Bw_CCFQtKyv";
const supabaseClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY);
const $ = (id) => document.getElementById(id);
const authPanel = $("authPanel"), appShell = $("appShell"), authStatus = $("authStatus");
let currentUser = null, activePartner = null, pollTimer = null, conversations = new Map();
const ITERATIONS = 600000, MAX_MESSAGE_LENGTH = 5000, MAX_PASSPHRASE_LENGTH = 256, MAGIC = "NTK3", VERSION = 1;

function setAuthStatus(text, type = "") { authStatus.textContent = text; authStatus.className = type; }
function setChatStatus(text, type = "") { $("chatStatus").textContent = text; $("chatStatus").className = type; }
function toBase64(bytes) { let binary = ""; for (const b of bytes) binary += String.fromCharCode(b); return btoa(binary); }
function fromBase64(text) { const binary = atob(text); return Uint8Array.from(binary, c => c.charCodeAt(0)); }
async function deriveKey(passphrase, salt) {
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function encryptMessage(plaintext, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt), header = `${MAGIC}.${VERSION}`, encoder = new TextEncoder();
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: encoder.encode(header), tagLength: 128 }, key, encoder.encode(plaintext));
  return "NTK3:" + toBase64(encoder.encode(JSON.stringify({ magic: MAGIC, version: VERSION, iterations: ITERATIONS, salt: toBase64(salt), iv: toBase64(iv), ciphertext: toBase64(new Uint8Array(encrypted)) })));
}
async function decryptMessage(encoded, passphrase) {
  if (!encoded.startsWith("NTK3:")) throw new Error("Unrecognised encrypted message.");
  let p; try { p = JSON.parse(new TextDecoder().decode(fromBase64(encoded.slice(5)))); } catch { throw new Error("The encrypted message is malformed."); }
  if (p.magic !== MAGIC || p.version !== VERSION || p.iterations !== ITERATIONS) throw new Error("Unsupported message format.");
  const salt = fromBase64(p.salt), iv = fromBase64(p.iv), ciphertext = fromBase64(p.ciphertext);
  if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 16 || ciphertext.length > MAX_MESSAGE_LENGTH * 4 + 16) throw new Error("Invalid encrypted message dimensions.");
  const key = await deriveKey(passphrase, salt);
  try { const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(`${MAGIC}.${VERSION}`), tagLength: 128 }, key, ciphertext); return new TextDecoder("utf-8", { fatal: true }).decode(plain); }
  catch { throw new Error("Unable to decrypt. Check the shared passphrase."); }
}

function showSignedOut() {
  currentUser = null; activePartner = null; conversations.clear(); clearInterval(pollTimer); pollTimer = null;
  appShell.hidden = true; authPanel.hidden = false; setAuthStatus("");
}
function showSignedIn(user) {
  currentUser = user; authPanel.hidden = true; appShell.hidden = false; $("signedInEmail").textContent = user.email || "NTk3 user";
  loadConversations();
}
async function authAction(mode) {
  const email = $("authEmail").value.trim().toLowerCase(), password = $("authPassword").value;
  if (!email || !password) return setAuthStatus("Enter your email and password.");
  if (mode === "signup" && password.length < 12) return setAuthStatus("Use a password of at least 12 characters.");
  $("signInBtn").disabled = $("signUpBtn").disabled = true; setAuthStatus(mode === "signin" ? "Signing in…" : "Creating account…");
  try {
    const result = mode === "signin" ? await supabaseClient.auth.signInWithPassword({ email, password }) : await supabaseClient.auth.signUp({ email, password });
    if (result.error) throw result.error;
    if (result.data.session) { showSignedIn(result.data.user); setAuthStatus("Welcome to NTk3!"); }
    else setAuthStatus("Check your email to confirm your account, then sign in.");
  } catch (e) { setAuthStatus(e.message || "Authentication failed."); }
  finally { $("signInBtn").disabled = $("signUpBtn").disabled = false; }
}
$("signInBtn").addEventListener("click", () => authAction("signin"));
$("signUpBtn").addEventListener("click", () => authAction("signup"));
$("signOutBtn").addEventListener("click", async () => { const { error } = await supabaseClient.auth.signOut(); if (error) setChatStatus(error.message); });
supabaseClient.auth.onAuthStateChange((_event, session) => { if (session) { if (!currentUser || currentUser.id !== session.user.id) showSignedIn(session.user); } else showSignedOut(); });

// Navigation tabs
function showTab(which) { const chat = which === "chat"; $("chatView").hidden = !chat; $("toolsView").hidden = chat; $("chatTab").classList.toggle("active", chat); $("toolsTab").classList.toggle("active", !chat); }
$("chatTab").addEventListener("click", () => showTab("chat")); $("toolsTab").addEventListener("click", () => showTab("tools"));

async function loadConversations() {
  if (!currentUser) return;
  const { data, error } = await supabaseClient.from("messages")
    .select("sender_id,recipient_id,created_at")
    .or(`sender_id.eq.${currentUser.id},recipient_id.eq.${currentUser.id}`)
    .order("created_at", { ascending: false }).limit(200);
  if (error) { $("findUserStatus").textContent = `Chat setup may be incomplete: ${error.message}`; return; }
  const ids = new Set();
  for (const row of data || []) {
    const otherId = row.sender_id === currentUser.id ? row.recipient_id : row.sender_id;
    if (otherId !== currentUser.id) ids.add(otherId);
  }
  if (!ids.size) { renderConversations(); return; }
  const { data: profiles, error: profileError } = await supabaseClient.from("profiles").select("id,email").in("id", [...ids]);
  if (profileError) { $("findUserStatus").textContent = `Could not load contacts: ${profileError.message}`; return; }
  for (const profile of profiles || []) conversations.set(profile.id, profile);
  renderConversations();
}

async function findUserByEmail(email) {
  // The profiles table is populated by the SQL trigger supplied with this project.
  const { data, error } = await supabaseClient.rpc("ntk3_find_profile_by_email", { p_email: email.toLowerCase() });
  if (error) throw error; const profile = Array.isArray(data) ? data[0] : data;
  if (!profile) throw new Error("No NTk3 account found for that email.");
  if (profile.id === currentUser.id) throw new Error("You cannot start a conversation with yourself.");
  return profile;
}
function addConversation(partner) { conversations.set(partner.id, partner); renderConversations(); openConversation(partner); }
$("findUserForm").addEventListener("submit", async (event) => {
  event.preventDefault(); if (!currentUser) return;
  const email = $("recipientEmail").value.trim().toLowerCase(); $("findUserStatus").textContent = "Looking for account…";
  try { const partner = await findUserByEmail(email); addConversation(partner); $("recipientEmail").value = ""; $("findUserStatus").textContent = "Conversation opened."; }
  catch (e) { $("findUserStatus").textContent = e.message || "Could not find account."; }
});
function renderConversations() {
  const list = $("conversationList"); list.replaceChildren(); $("conversationCount").textContent = String(conversations.size);
  if (!conversations.size) { list.innerHTML = '<div class="empty-list">No conversations yet.<br>Start one using an email above.</div>'; return; }
  for (const partner of conversations.values()) {
    const button = document.createElement("button"); button.type = "button"; button.className = "conversation-item" + (activePartner?.id === partner.id ? " selected" : "");
    const avatar = document.createElement("span"); avatar.className = "avatar small"; avatar.textContent = (partner.email || "N").slice(0, 1).toUpperCase();
    const info = document.createElement("span"); info.className = "conversation-info"; const title = document.createElement("strong"); title.textContent = partner.email; const sub = document.createElement("small"); sub.textContent = "Private conversation"; info.append(title, sub); button.append(avatar, info); button.addEventListener("click", () => openConversation(partner)); list.append(button);
  }
}
function openConversation(partner) {
  activePartner = partner; $("chatEmpty").hidden = true; $("activeChat").hidden = false;
  $("chatPersonName").textContent = partner.email.split("@")[0] || "NTk3 user"; $("chatPersonEmail").textContent = partner.email; $("chatAvatar").textContent = partner.email.slice(0, 1).toUpperCase();
  renderConversations(); loadMessages(); clearInterval(pollTimer); pollTimer = setInterval(loadMessages, 5000);
  setChatStatus("Use the same shared passphrase on both devices.");
}
function messageBubble(row, text, failed = false) {
  const wrap = document.createElement("article"); wrap.className = "message-bubble " + (row.sender_id === currentUser.id ? "mine" : "theirs");
  const body = document.createElement("p"); body.textContent = text;
  const meta = document.createElement("div"); meta.className = "message-meta"; const date = new Date(row.created_at); meta.textContent = `${row.sender_id === currentUser.id ? "You" : activePartner.email.split("@")[0]} · ${date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}${row.sender_id === currentUser.id && row.delivered_at ? " · delivered" : ""}`;
  if (failed) body.classList.add("decrypt-error"); wrap.append(body, meta); return wrap;
}
async function loadMessages() {
  if (!currentUser || !activePartner) return;
  const { data, error } = await supabaseClient.from("messages").select("id,sender_id,recipient_id,ciphertext,created_at,delivered_at").or(`and(sender_id.eq.${currentUser.id},recipient_id.eq.${activePartner.id}),and(sender_id.eq.${activePartner.id},recipient_id.eq.${currentUser.id})`).order("created_at", { ascending: true }).limit(100);
  if (error) { setChatStatus(`Could not load messages: ${error.message}`); return; }
  const area = $("messagesArea"), passphrase = $("chatPassphrase").value;
  area.replaceChildren();
  if (!data?.length) { area.innerHTML = '<div class="empty-messages">No messages yet. Say hello.</div>'; return; }
  for (const row of data) {
    let text = "Encrypted message — enter the shared passphrase above to read it."; let failed = false;
    if (passphrase) { try { text = await decryptMessage(row.ciphertext, passphrase); } catch { text = "Unable to decrypt this message. Check the shared passphrase."; failed = true; } }
    area.append(messageBubble(row, text, failed));
  }
  area.scrollTop = area.scrollHeight;
  const received = data.filter(row => row.recipient_id === currentUser.id && !row.delivered_at).map(row => row.id);
  if (received.length) await supabaseClient.from("messages").update({ delivered_at: new Date().toISOString() }).in("id", received);
}
$("chatPassphrase").addEventListener("input", () => { clearTimeout(window.ntk3DecryptTimer); window.ntk3DecryptTimer = setTimeout(loadMessages, 250); });
$("sendMessageForm").addEventListener("submit", async (event) => {
  event.preventDefault(); if (!currentUser || !activePartner) return setChatStatus("Choose a conversation first.");
  const text = $("chatMessageInput").value.trim(), passphrase = $("chatPassphrase").value;
  if (!text) return; if (!passphrase.trim()) return setChatStatus("Enter the shared chat passphrase first."); if (passphrase.length > MAX_PASSPHRASE_LENGTH) return setChatStatus("Passphrase is too long."); if (text.length > MAX_MESSAGE_LENGTH) return setChatStatus("Message is too long.");
  const button = $("sendMessageBtn"); button.disabled = true; setChatStatus("Encrypting and sending…");
  try {
    const ciphertext = await encryptMessage(text, passphrase);
    const { error } = await supabaseClient.from("messages").insert({ sender_id: currentUser.id, recipient_id: activePartner.id, ciphertext });
    if (error) throw error; $("chatMessageInput").value = ""; setChatStatus("Message sent. The server received encrypted text only."); await loadMessages();
  } catch (e) { setChatStatus(`Could not send message: ${e.message || "unknown error"}`); }
  finally { button.disabled = false; }
});

// Existing local encrypt/decrypt tool
let currentMode = "encrypt";
function setStatus(text, type = "") { $("statusMessage").textContent = text; $("statusMessage").className = type; }
function setMode(mode) { currentMode = mode; const enc = mode === "encrypt"; $("encryptMode").classList.toggle("active", enc); $("decryptMode").classList.toggle("active", !enc); $("actionText").textContent = enc ? "Encrypt Message" : "Decrypt Message"; $("actionIcon").textContent = enc ? "♙" : "◉"; $("message").placeholder = enc ? "Write your message here…" : "Paste your NTk3 encrypted message here…"; setStatus(enc ? "Ready to encrypt." : "Ready to decrypt."); }
$("encryptMode").addEventListener("click", () => setMode("encrypt")); $("decryptMode").addEventListener("click", () => setMode("decrypt"));
$("message").addEventListener("input", () => { $("charCount").textContent = `${$("message").value.length} / 5000`; });
$("togglePassword").addEventListener("click", () => { const input = $("passphrase"), show = input.type === "password"; input.type = show ? "text" : "password"; $("togglePassword").setAttribute("aria-label", show ? "Hide passphrase" : "Show passphrase"); });
$("actionBtn").addEventListener("click", async () => {
  const message = $("message").value, passphrase = $("passphrase").value;
  if (!window.isSecureContext || !crypto.subtle) return setStatus("Secure encryption requires HTTPS or localhost.", "error");
  if (!message.trim()) return setStatus("Please enter a message first.", "error"); if (message.length > MAX_MESSAGE_LENGTH) return setStatus("Message exceeds 5000 characters.", "error"); if (!passphrase.trim()) return setStatus("Please enter your passphrase.", "error"); if (passphrase.length > MAX_PASSPHRASE_LENGTH) return setStatus("Passphrase is too long.", "error");
  $("actionBtn").disabled = true; $("actionText").textContent = currentMode === "encrypt" ? "Encrypting…" : "Decrypting…";
  try { $("result").value = currentMode === "encrypt" ? await encryptMessage(message, passphrase) : await decryptMessage(message.trim(), passphrase); setStatus(currentMode === "encrypt" ? "Message encrypted successfully." : "Message decrypted successfully.", "success"); }
  catch (e) { setStatus(e.message || "Something went wrong.", "error"); }
  finally { $("actionBtn").disabled = false; $("actionText").textContent = currentMode === "encrypt" ? "Encrypt Message" : "Decrypt Message"; }
});
$("copyBtn").addEventListener("click", async () => { if (!$("result").value) return setStatus("There is no result to copy.", "error"); try { await navigator.clipboard.writeText($("result").value); setStatus("Copied to clipboard.", "success"); } catch { $("result").select(); setStatus(document.execCommand("copy") ? "Copied to clipboard." : "Select and copy manually.", "success"); } });
$("clearBtn").addEventListener("click", () => { $("message").value = ""; $("result").value = ""; $("passphrase").value = ""; $("charCount").textContent = "0 / 5000"; setStatus("Fields cleared."); });
$("themeBtn").addEventListener("click", () => { document.body.classList.toggle("light"); const light = document.body.classList.contains("light"); $("themeBtn").textContent = light ? "☾" : "☼"; document.querySelector('meta[name="theme-color"]').content = light ? "#f3f6ff" : "#080b12"; });

(async () => { const { data, error } = await supabaseClient.auth.getSession(); if (error) setAuthStatus("Could not restore your session. Please sign in again."); else if (data.session) showSignedIn(data.session.user); else showSignedOut(); })();

if ("serviceWorker" in navigator && location.protocol.startsWith("http")) {
  window.addEventListener("load", () => navigator.serviceWorker.register("./service-worker.js").catch(() => {}));
}
