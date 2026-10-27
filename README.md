<div align="center">

# 🔐 Secure File Locker - CyberVault

### 🌐 [👉 CLICK HERE FOR LIVE DEMO 👈](https://gobalakrishnan-p.github.io/secure-file-locker/)

[![Live Demo](https://img.shields.io/badge/🚀_LIVE_DEMO-OPEN_WEBSITE-00c853?style=for-the-badge&logo=github)](https://gobalakrishnan-p.github.io/secure-file-locker/)
![Security](https://img.shields.io/badge/Encryption-AES--256--GCM-blue?style=for-the-badge)
![Tech](https://img.shields.io/badge/Built_With-HTML5_|_CSS3_|_JS-orange?style=for-the-badge)

</div>

---

## 📖 About The Project

**Secure File Locker** is a client-side, zero-knowledge web application that allows users to lock (encrypt) and unlock (decrypt) any file type—including **PDFs, Images, Videos, Audio, and Text**—directly inside the browser before sharing or storing them.

🔗 **Live Website:** [**Live Demo**](https://gobalakrishnan-p.github.io/secure-file-locker/)

---

## ✨ Key Features

- **🛡️ End-to-End Client-Side Security:** All encryption and decryption happen locally inside your browser using the native **Web Crypto API**. No files or passwords are ever uploaded to any server.
- **📁 Universal File Support:** Lock and unlock PDFs, Photos (JPG, PNG), Videos (MP4), Audio (MP3), Documents, and plain text.
- **🔑 Document-Specific Passwords:** Every encrypted file is protected by its own custom password using **PBKDF2** (100,000 iterations + random cryptographic salt) and **AES-256-GCM** encryption.
- **🚫 Tamper-Proof Protection:** Encrypted files cannot be opened or viewed by unauthorized users or third-party software without the exact decryption password.
- **💻 User-Friendly Interface:** Clean, modern dark-mode cybersecurity interface with password strength indicators and instant file restoration.

---

## 🛠️ Technology Stack

- **Frontend:** HTML5, CSS3 (Responsive Dark UI)
- **Scripting:** Vanilla JavaScript (ES6+)
- **Cryptography:** Browser Web Crypto API (`window.crypto.subtle`), AES-GCM (256-bit), PBKDF2 (SHA-256)
- **Hosting:** GitHub Pages

---

## 🚀 How to Use

1. **Open the App:** Visit the [**Live Demo**](https://gobalakrishnan-p.github.io/secure-file-locker/) and create a local account / log in.
2. **Lock a File (Encrypt):**
   - Select or drag-and-drop any file (PDF, Image, Video, etc.).
   - Set a strong password specifically for that file.
   - Download the protected encrypted file.
3. **Unlock a File (Decrypt):**
   - Upload the encrypted file back into the Decryption tab.
   - Enter the exact password set for that file.
   - Preview or download your restored original file instantly.

---

## 🔒 Security Note

Because this project uses true **Zero-Knowledge Encryption**, your file passwords are never stored on any server. If you forget the password set for a specific file, the file cannot be recovered.
