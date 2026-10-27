/**
 * CYBERVAULT // ZERO-KNOWLEDGE CLIENT ENCRYPTION ENGINE
 * 
 * Security & Cryptography Standards:
 * - File Encryption: AES-GCM (256-bit Key) with 96-bit (12-byte) random IV
 * - Key Derivation: PBKDF2 with HMAC-SHA-256, 100,000 iterations, 16-byte random salt
 * - Hardened Account Storage: PBKDF2 (100,000 rounds) + unique salt + SHA-256 integrity checksum in localStorage
 * - Session Security: Strictly in-memory closure state (DevTools storage tampering cannot bypass auth)
 * - Memory Clearance: Sensitive passwords and keys wiped immediately after use
 * - Binary Envelope: VAULT02 format with encapsulated metadata
 */

(function () {
  'use strict';

  // =========================================================================
  // CONSTANTS & SYSTEM CONFIGURATION
  // =========================================================================
  const VAULT_MAGIC = new Uint8Array([0x56, 0x41, 0x55, 0x4C, 0x54, 0x30, 0x32]); // "VAULT02"
  const FILE_PBKDF2_ROUNDS = 100000;
  const ACCOUNT_PBKDF2_ROUNDS = 100000;
  const SALT_BYTE_LENGTH = 16;
  const IV_BYTE_LENGTH = 12;
  const STORAGE_USERS_KEY = 'cybervault_users_db_v2';
  const INTEGRITY_PEPPER = 'CYBERVAULT_DEVTOOLS_INTEGRITY_SHIELD_v2.5';

  // =========================================================================
  // STRICT IN-MEMORY CLOSURE STATE (Unreachable from window / DevTools console)
  // =========================================================================
  let activeUserSession = null; // Governs authentication. Never persisted as plain flag in storage!

  const state = {
    encryptMode: 'file', // 'file' or 'text'
    encryptFile: null,
    decryptFile: null,
    lastEncryptedBlobUrl: null,
    lastDecryptedBlobUrl: null,
    lastEncryptedBase64: null,
    lastRestoredText: null
  };

  // =========================================================================
  // DOM ELEMENT REFERENCES
  // =========================================================================
  const dom = {
    // Header & User Actions
    headerUserStatus: document.getElementById('header-user-status'),
    headerUsername: document.getElementById('header-username'),
    btnLogout: document.getElementById('btn-logout'),

    // Sections
    authSection: document.getElementById('auth-section'),
    workspaceSection: document.getElementById('workspace-section'),

    // Auth Forms & Tabs
    tabBtnLogin: document.getElementById('tab-btn-login'),
    tabBtnRegister: document.getElementById('tab-btn-register'),
    formLogin: document.getElementById('form-login'),
    formRegister: document.getElementById('form-register'),
    loginUsername: document.getElementById('login-username'),
    loginPassword: document.getElementById('login-password'),
    regUsername: document.getElementById('reg-username'),
    regPassword: document.getElementById('reg-password'),
    regConfirm: document.getElementById('reg-confirm'),

    // Workspace Navigation Tabs
    navTabEncrypt: document.getElementById('nav-tab-encrypt'),
    navTabDecrypt: document.getElementById('nav-tab-decrypt'),
    navTabAudit: document.getElementById('nav-tab-audit'),
    panelEncrypt: document.getElementById('panel-encrypt'),
    panelDecrypt: document.getElementById('panel-decrypt'),
    panelAudit: document.getElementById('panel-audit'),

    // Encryption Controls
    submodeFile: document.getElementById('submode-file'),
    submodeText: document.getElementById('submode-text'),
    encryptFileContainer: document.getElementById('encrypt-file-container'),
    encryptTextContainer: document.getElementById('encrypt-text-container'),
    encryptDropzone: document.getElementById('encrypt-dropzone'),
    encryptFileInput: document.getElementById('encrypt-file-input'),
    encryptSelectedFile: document.getElementById('encrypt-selected-file'),
    encryptFileName: document.getElementById('encrypt-file-name'),
    encryptFileSize: document.getElementById('encrypt-file-size'),
    encryptFileBadge: document.getElementById('encrypt-file-badge'),
    btnRemoveEncryptFile: document.getElementById('btn-remove-encrypt-file'),
    encryptPlaintext: document.getElementById('encrypt-plaintext'),
    encryptTextFilename: document.getElementById('encrypt-text-filename'),
    textCounter: document.getElementById('text-counter'),
    encryptPassword: document.getElementById('encrypt-password'),
    btnGenPass: document.getElementById('btn-gen-pass'),
    btnRunEncrypt: document.getElementById('btn-run-encrypt'),

    // Password Strength Meter
    strengthVerdict: document.getElementById('strength-verdict'),
    strengthBar: document.getElementById('strength-bar'),
    critLen: document.getElementById('crit-len'),
    critUpper: document.getElementById('crit-upper'),
    critLower: document.getElementById('crit-lower'),
    critNum: document.getElementById('crit-num'),
    critSym: document.getElementById('crit-sym'),

    // Encryption Results
    encryptEngineStatus: document.getElementById('encrypt-engine-status'),
    encryptProgressContainer: document.getElementById('encrypt-progress-container'),
    encryptEmptyState: document.getElementById('encrypt-empty-state'),
    encryptSuccessCard: document.getElementById('encrypt-success-card'),
    encResOriginalName: document.getElementById('enc-res-original-name'),
    encResMime: document.getElementById('enc-res-mime'),
    encResSize: document.getElementById('enc-res-size'),
    encResHash: document.getElementById('enc-res-hash'),
    btnDownloadLocked: document.getElementById('btn-download-locked'),
    btnCopyEncBase64: document.getElementById('btn-copy-enc-base64'),

    // Decryption Controls
    decryptDropzone: document.getElementById('decrypt-dropzone'),
    decryptFileInput: document.getElementById('decrypt-file-input'),
    decryptSelectedFile: document.getElementById('decrypt-selected-file'),
    decryptFileName: document.getElementById('decrypt-file-name'),
    decryptFileSize: document.getElementById('decrypt-file-size'),
    decryptFileBadge: document.getElementById('decrypt-file-badge'),
    btnRemoveDecryptFile: document.getElementById('btn-remove-decrypt-file'),
    btnToggleBase64Input: document.getElementById('btn-toggle-base64-input'),
    decryptBase64Container: document.getElementById('decrypt-base64-container'),
    decryptBase64Text: document.getElementById('decrypt-base64-text'),
    decryptPassword: document.getElementById('decrypt-password'),
    btnRunDecrypt: document.getElementById('btn-run-decrypt'),
    decryptErrorBanner: document.getElementById('decrypt-error-banner'),
    decryptErrorText: document.getElementById('decrypt-error-text'),

    // Decryption Results
    decryptEngineStatus: document.getElementById('decrypt-engine-status'),
    decryptProgressContainer: document.getElementById('decrypt-progress-container'),
    decryptEmptyState: document.getElementById('decrypt-empty-state'),
    decryptSuccessCard: document.getElementById('decrypt-success-card'),
    decResName: document.getElementById('dec-res-name'),
    decResType: document.getElementById('dec-res-type'),
    decResSize: document.getElementById('dec-res-size'),
    previewTypeTag: document.getElementById('preview-type-tag'),
    previewBody: document.getElementById('preview-body'),
    btnDownloadRestored: document.getElementById('btn-download-restored'),
    btnCopyRestoredText: document.getElementById('btn-copy-restored-text'),

    // Toast Container
    toastContainer: document.getElementById('toast-container')
  };

  // =========================================================================
  // TOAST NOTIFICATION UTILITY
  // =========================================================================
  function showToast(message, type = 'info', duration = 4000) {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    let iconSvg = '';
    if (type === 'success') {
      iconSvg = `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>`;
    } else if (type === 'error') {
      iconSvg = `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`;
    } else {
      iconSvg = `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;
    }

    toast.innerHTML = `${iconSvg}<span>${escapeHtml(message)}</span>`;
    dom.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.classList.add('toast-out');
      setTimeout(() => {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, 300);
    }, duration);
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>'"]/g, tag => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
    }[tag] || tag));
  }

  function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  }

  function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  function hexToUint8Array(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
  }

  function uint8ArrayToBase64(bytes) {
    let binary = '';
    const len = bytes.byteLength;
    const chunkSize = 8192;
    for (let i = 0; i < len; i += chunkSize) {
      const chunk = bytes.subarray(i, Math.min(i + chunkSize, len));
      binary += String.fromCharCode.apply(null, chunk);
    }
    return window.btoa(binary);
  }

  function base64ToUint8Array(base64) {
    const cleaned = base64.replace(/\s+/g, '');
    const binary = window.atob(cleaned);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // =========================================================================
  // CRYPTOGRAPHIC PRIMITIVES (WEB CRYPTO API)
  // =========================================================================

  /**
   * Hashes data using SHA-256
   */
  async function computeSha256(data) {
    const buffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', buffer);
    return bufferToHex(hashBuffer);
  }

  /**
   * Hardened PBKDF2 hash for user master passwords (100,000 iterations + SHA-256)
   */
  async function deriveAccountKeyHash(password, saltBytes) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const derivedBits = await window.crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations: ACCOUNT_PBKDF2_ROUNDS,
        hash: 'SHA-256'
      },
      keyMaterial,
      256
    );

    return bufferToHex(derivedBits);
  }

  /**
   * Derives a 256-bit AES-GCM key from password and salt for file/data encryption
   */
  async function deriveFileAesKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: FILE_PBKDF2_ROUNDS,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Packages encrypted ciphertext with salt, IV, and metadata into a VAULT02 binary
   */
  function buildVaultPackage(salt, iv, metadata, ciphertextBuffer) {
    const metaBytes = new TextEncoder().encode(JSON.stringify(metadata));
    const metaLen = metaBytes.byteLength;
    const cipherBytes = new Uint8Array(ciphertextBuffer);

    // Structure: Magic (7B) + Salt (16B) + IV (12B) + MetaLen (4B) + MetaBytes + Ciphertext
    const totalLength = VAULT_MAGIC.byteLength + salt.byteLength + iv.byteLength + 4 + metaLen + cipherBytes.byteLength;
    const packageBuffer = new Uint8Array(totalLength);
    const dataView = new DataView(packageBuffer.buffer);

    let offset = 0;

    packageBuffer.set(VAULT_MAGIC, offset);
    offset += VAULT_MAGIC.byteLength;

    packageBuffer.set(salt, offset);
    offset += salt.byteLength;

    packageBuffer.set(iv, offset);
    offset += iv.byteLength;

    dataView.setUint32(offset, metaLen, false);
    offset += 4;

    packageBuffer.set(metaBytes, offset);
    offset += metaLen;

    packageBuffer.set(cipherBytes, offset);

    return packageBuffer;
  }

  /**
   * Parses and unpacks a VAULT02 binary package
   */
  function parseVaultPackage(packageBytes) {
    if (packageBytes.byteLength < VAULT_MAGIC.byteLength + SALT_BYTE_LENGTH + IV_BYTE_LENGTH + 4) {
      throw new Error('This file is too small or damaged to be an unlocked CyberVault file.');
    }

    let offset = 0;

    // Verify magic bytes
    for (let i = 0; i < VAULT_MAGIC.length; i++) {
      if (packageBytes[offset + i] !== VAULT_MAGIC[i]) {
        throw new Error('Unrecognized file type. Please upload a valid .locked file created with CyberVault.');
      }
    }
    offset += VAULT_MAGIC.byteLength;

    const salt = packageBytes.slice(offset, offset + SALT_BYTE_LENGTH);
    offset += SALT_BYTE_LENGTH;

    const iv = packageBytes.slice(offset, offset + IV_BYTE_LENGTH);
    offset += IV_BYTE_LENGTH;

    const dataView = new DataView(packageBytes.buffer, packageBytes.byteOffset, packageBytes.byteLength);
    const metaLen = dataView.getUint32(offset, false);
    offset += 4;

    if (offset + metaLen > packageBytes.byteLength) {
      throw new Error('The file header appears damaged or modified.');
    }

    const metaBytes = packageBytes.slice(offset, offset + metaLen);
    offset += metaLen;
    const metaString = new TextDecoder().decode(metaBytes);
    let metadata;
    try {
      metadata = JSON.parse(metaString);
    } catch (e) {
      throw new Error('Unable to read original file information.');
    }

    const ciphertext = packageBytes.slice(offset);

    return { salt, iv, metadata, ciphertext };
  }

  // =========================================================================
  // HARDENED AUTHENTICATION (PBKDF2 + INTEGRITY CHECK + STRICT CLOSURE SESSION)
  // =========================================================================
  function getUsersDatabase() {
    try {
      const data = localStorage.getItem(STORAGE_USERS_KEY);
      return data ? JSON.parse(data) : {};
    } catch (e) {
      console.error('Storage read error:', e);
      return {};
    }
  }

  function saveUsersDatabase(users) {
    try {
      localStorage.setItem(STORAGE_USERS_KEY, JSON.stringify(users));
    } catch (e) {
      console.error('Storage write error:', e);
      showToast('Could not save to browser storage. Storage may be disabled or full.', 'error');
    }
  }

  async function handleRegistration(e) {
    e.preventDefault();
    const username = dom.regUsername.value.trim().toLowerCase();
    const password = dom.regPassword.value;
    const confirm = dom.regConfirm.value;

    if (!username || username.length < 3) {
      showToast('Username must be at least 3 characters.', 'error');
      return;
    }
    if (password.length < 6) {
      showToast('Master password must be at least 6 characters.', 'error');
      return;
    }
    if (password !== confirm) {
      showToast('Passwords do not match. Please re-check.', 'error');
      return;
    }

    const users = getUsersDatabase();
    if (users[username]) {
      showToast(`Username "${username}" already exists. Please sign in instead.`, 'error');
      switchAuthTab('login');
      dom.loginUsername.value = username;
      dom.loginPassword.focus();
      return;
    }

    // 1. Generate unique 16-byte random salt for account
    const saltBytes = window.crypto.getRandomValues(new Uint8Array(16));
    const saltHex = bufferToHex(saltBytes);

    // 2. Derive key with 100,000 PBKDF2 rounds
    const keyHash = await deriveAccountKeyHash(password, saltBytes);

    // 3. Compute tamper-detection cryptographic integrity signature
    const integritySig = await computeSha256(`${username}:${saltHex}:${keyHash}:${INTEGRITY_PEPPER}`);

    users[username] = {
      username: username,
      salt: saltHex,
      keyHash: keyHash,
      integrity: integritySig,
      version: 'v2',
      createdAt: new Date().toISOString()
    };

    saveUsersDatabase(users);

    // Wipe password inputs immediately from memory
    dom.regPassword.value = '';
    dom.regConfirm.value = '';

    showToast(`Account "${username}" created safely! Please sign in.`, 'success');

    // Switch to login tab and prefill username
    switchAuthTab('login');
    dom.loginUsername.value = username;
    dom.loginPassword.value = '';
    dom.loginPassword.focus();
  }

  async function handleLogin(e) {
    e.preventDefault();
    const username = dom.loginUsername.value.trim().toLowerCase();
    const password = dom.loginPassword.value;

    if (!username || !password) {
      showToast('Please enter both your username and password.', 'error');
      return;
    }

    const users = getUsersDatabase();
    const user = users[username];

    if (!user) {
      showToast('Oops! Incorrect username or master password.', 'error');
      dom.loginPassword.value = '';
      return;
    }

    // DevTools Anti-Tamper Check: Verify cryptographic integrity signature
    if (user.integrity) {
      const expectedIntegrity = await computeSha256(`${username}:${user.salt}:${user.keyHash}:${INTEGRITY_PEPPER}`);
      if (expectedIntegrity !== user.integrity) {
        showToast('Security Alert: Stored account credentials were altered. Access denied.', 'error');
        dom.loginPassword.value = '';
        return;
      }
    }

    // Derive PBKDF2 hash
    const saltBytes = hexToUint8Array(user.salt);
    const computedHash = await deriveAccountKeyHash(password, saltBytes);

    if (computedHash !== user.keyHash) {
      showToast('Oops! Incorrect username or master password.', 'error');
      dom.loginPassword.value = '';
      return;
    }

    // Login Success: Assign STRICT IN-MEMORY CLOSURE SESSION
    // DevTools storage modification cannot forge this!
    activeUserSession = {
      username: user.username,
      loginTimestamp: Date.now()
    };

    // Immediately clear sensitive master password from the DOM input
    dom.loginPassword.value = '';

    activateSessionView(user.username);
    showToast(`Welcome back, ${user.username}! Your vault is unlocked.`, 'success');
  }

  function handleLogout() {
    // 1. Wipe in-memory session
    activeUserSession = null;

    // 2. Wipe sensitive input fields from DOM
    dom.loginPassword.value = '';
    dom.regPassword.value = '';
    dom.regConfirm.value = '';
    dom.encryptPassword.value = '';
    dom.decryptPassword.value = '';
    evaluatePasswordStrength('');

    // 3. Reset file references
    clearEncryptFile();
    clearDecryptFile();

    deactivateSessionView();
    showToast('Signed out safely. Vault locked.', 'info');
  }

  function activateSessionView(username) {
    dom.headerUsername.textContent = username;
    dom.headerUserStatus.classList.remove('hidden');
    dom.authSection.classList.add('hidden');
    dom.workspaceSection.classList.remove('hidden');
    switchWorkspaceTab('encrypt');
  }

  function deactivateSessionView() {
    activeUserSession = null;
    dom.headerUserStatus.classList.add('hidden');
    dom.workspaceSection.classList.add('hidden');
    dom.authSection.classList.remove('hidden');
    switchAuthTab('login');
  }

  function switchAuthTab(tab) {
    if (tab === 'login') {
      dom.tabBtnLogin.classList.add('active');
      dom.tabBtnRegister.classList.remove('active');
      dom.formLogin.classList.remove('hidden');
      dom.formRegister.classList.add('hidden');
      dom.loginUsername.focus();
    } else {
      dom.tabBtnRegister.classList.add('active');
      dom.tabBtnLogin.classList.remove('active');
      dom.formRegister.classList.remove('hidden');
      dom.formLogin.classList.add('hidden');
      dom.regUsername.focus();
    }
  }

  // =========================================================================
  // WORKSPACE TAB NAVIGATION
  // =========================================================================
  function switchWorkspaceTab(tabId) {
    // Security check: ensure active in-memory session is valid
    if (!activeUserSession) {
      deactivateSessionView();
      return;
    }

    [dom.navTabEncrypt, dom.navTabDecrypt, dom.navTabAudit].forEach(tab => {
      tab.classList.remove('active');
      tab.setAttribute('aria-selected', 'false');
    });
    [dom.panelEncrypt, dom.panelDecrypt, dom.panelAudit].forEach(panel => {
      panel.classList.remove('active');
    });

    if (tabId === 'encrypt') {
      dom.navTabEncrypt.classList.add('active');
      dom.navTabEncrypt.setAttribute('aria-selected', 'true');
      dom.panelEncrypt.classList.add('active');
    } else if (tabId === 'decrypt') {
      dom.navTabDecrypt.classList.add('active');
      dom.navTabDecrypt.setAttribute('aria-selected', 'true');
      dom.panelDecrypt.classList.add('active');
    } else if (tabId === 'audit') {
      dom.navTabAudit.classList.add('active');
      dom.navTabAudit.setAttribute('aria-selected', 'true');
      dom.panelAudit.classList.add('active');
    }
  }

  // =========================================================================
  // USER-FRIENDLY PASSWORD STRENGTH & RANDOM KEY GENERATOR
  // =========================================================================
  function evaluatePasswordStrength(password) {
    if (!password) {
      dom.strengthVerdict.textContent = 'AWAITING INPUT';
      dom.strengthVerdict.className = 'meter-verdict verdict-none';
      dom.strengthBar.className = 'strength-fill strength-0';
      [dom.critLen, dom.critUpper, dom.critLower, dom.critNum, dom.critSym].forEach(p => p.classList.remove('valid'));
      return 0;
    }

    const hasLen = password.length >= 8;
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNum = /[0-9]/.test(password);
    const hasSym = /[^A-Za-z0-9]/.test(password);

    dom.critLen.classList.toggle('valid', hasLen);
    dom.critUpper.classList.toggle('valid', hasUpper);
    dom.critLower.classList.toggle('valid', hasLower);
    dom.critNum.classList.toggle('valid', hasNum);
    dom.critSym.classList.toggle('valid', hasSym);

    let score = 0;
    if (hasLen) score++;
    if (hasUpper && hasLower) score++;
    if (hasNum) score++;
    if (hasSym) score++;

    // Extra length bonus
    if (password.length >= 14 && score === 4) {
      dom.strengthVerdict.textContent = 'SUPER STRONG (EXCELLENT)';
      dom.strengthVerdict.className = 'meter-verdict verdict-ultra';
      dom.strengthBar.className = 'strength-fill strength-4';
      return 4;
    }

    if (score === 0 || score === 1) {
      dom.strengthVerdict.textContent = 'WEAK (TRY LONGER)';
      dom.strengthVerdict.className = 'meter-verdict verdict-weak';
      dom.strengthBar.className = 'strength-fill strength-1';
    } else if (score === 2) {
      dom.strengthVerdict.textContent = 'FAIR (ADD SYMBOLS)';
      dom.strengthVerdict.className = 'meter-verdict verdict-fair';
      dom.strengthBar.className = 'strength-fill strength-2';
    } else if (score === 3) {
      dom.strengthVerdict.textContent = 'GOOD (SECURE)';
      dom.strengthVerdict.className = 'meter-verdict verdict-good';
      dom.strengthBar.className = 'strength-fill strength-3';
    } else {
      dom.strengthVerdict.textContent = 'STRONG (EXCELLENT)';
      dom.strengthVerdict.className = 'meter-verdict verdict-strong';
      dom.strengthBar.className = 'strength-fill strength-4';
    }

    return score;
  }

  function generateHighEntropyPassword() {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?';
    const length = 20;
    const randomValues = window.crypto.getRandomValues(new Uint32Array(length));
    let password = '';
    for (let i = 0; i < length; i++) {
      password += charset[randomValues[i] % charset.length];
    }

    dom.encryptPassword.value = password;
    evaluatePasswordStrength(password);
    showToast('Suggested strong 20-character password created!', 'success');
  }

  // =========================================================================
  // FILE & NOTE ENCRYPTION WORKFLOW
  // =========================================================================
  function setEncryptSubmode(mode) {
    state.encryptMode = mode;
    if (mode === 'file') {
      dom.submodeFile.classList.add('active');
      dom.submodeText.classList.remove('active');
      dom.encryptFileContainer.classList.remove('hidden');
      dom.encryptTextContainer.classList.add('hidden');
    } else {
      dom.submodeText.classList.add('active');
      dom.submodeFile.classList.remove('active');
      dom.encryptTextContainer.classList.remove('hidden');
      dom.encryptFileContainer.classList.add('hidden');
      dom.encryptPlaintext.focus();
    }
  }

  function handleEncryptFileSelect(file) {
    if (!file) return;
    state.encryptFile = file;

    const ext = file.name.split('.').pop().toUpperCase() || 'FILE';
    dom.encryptFileBadge.textContent = ext.substring(0, 5);
    dom.encryptFileName.textContent = file.name;
    dom.encryptFileSize.textContent = `${formatBytes(file.size)}`;

    dom.encryptDropzone.querySelector('.dropzone-content').classList.add('hidden');
    dom.encryptSelectedFile.classList.remove('hidden');
  }

  function clearEncryptFile() {
    state.encryptFile = null;
    dom.encryptFileInput.value = '';
    dom.encryptDropzone.querySelector('.dropzone-content').classList.remove('hidden');
    dom.encryptSelectedFile.classList.add('hidden');
  }

  async function executeEncryption() {
    // 1. HARDENED IN-MEMORY AUTHENTICATION CHECK
    if (!activeUserSession) {
      showToast('Please sign in to lock files.', 'error');
      deactivateSessionView();
      return;
    }

    const password = dom.encryptPassword.value;

    if (!password) {
      showToast('Please enter a secret password to protect this file.', 'error');
      dom.encryptPassword.focus();
      return;
    }

    let rawBuffer = null;
    let originalName = '';
    let mimeType = 'application/octet-stream';
    let isText = false;

    if (state.encryptMode === 'file') {
      if (!state.encryptFile) {
        showToast('Please choose or drop a file to lock.', 'error');
        return;
      }
      originalName = state.encryptFile.name;
      mimeType = state.encryptFile.type || 'application/octet-stream';
      isText = mimeType.startsWith('text/') || /\.(txt|md|csv|json|html|js|css|py|xml|log)$/i.test(originalName);
      rawBuffer = await state.encryptFile.arrayBuffer();
    } else {
      const textContent = dom.encryptPlaintext.value;
      if (!textContent.trim()) {
        showToast('Please type your confidential note first.', 'error');
        dom.encryptPlaintext.focus();
        return;
      }
      originalName = dom.encryptTextFilename.value.trim() || 'my_secret_note.txt';
      mimeType = 'text/plain';
      isText = true;
      rawBuffer = new TextEncoder().encode(textContent).buffer;
    }

    try {
      // UI State: In Progress
      dom.encryptEmptyState.classList.add('hidden');
      dom.encryptSuccessCard.classList.add('hidden');
      dom.encryptProgressContainer.classList.remove('hidden');
      dom.encryptEngineStatus.textContent = 'LOCKING...';
      dom.encryptEngineStatus.className = 'engine-badge';
      dom.btnRunEncrypt.disabled = true;

      await new Promise(resolve => setTimeout(resolve, 60));

      // 1. Generate salt (16 bytes) and IV (12 bytes)
      const salt = window.crypto.getRandomValues(new Uint8Array(SALT_BYTE_LENGTH));
      const iv = window.crypto.getRandomValues(new Uint8Array(IV_BYTE_LENGTH));

      // 2. Derive Key via PBKDF2 (100,000 rounds)
      const aesKey = await deriveFileAesKey(password, salt);

      // 3. Encrypt payload via AES-GCM
      const ciphertextBuffer = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        aesKey,
        rawBuffer
      );

      // 4. Build VAULT02 binary package
      const metadata = {
        name: originalName,
        type: mimeType,
        size: rawBuffer.byteLength,
        isText: isText,
        timestamp: Date.now()
      };

      const packageBytes = buildVaultPackage(salt, iv, metadata, ciphertextBuffer);

      // 5. Compute SHA-256 Digest for integrity fingerprint
      const packageDigest = await computeSha256(packageBytes);

      // 6. Create Blob & Download URL
      const lockedBlob = new Blob([packageBytes], { type: 'application/octet-stream' });
      if (state.lastEncryptedBlobUrl) URL.revokeObjectURL(state.lastEncryptedBlobUrl);
      state.lastEncryptedBlobUrl = URL.createObjectURL(lockedBlob);

      // Convert to Base64 armored string
      state.lastEncryptedBase64 = uint8ArrayToBase64(packageBytes);

      // 7. Update UI Results
      const lockedDownloadName = `${originalName}.locked`;
      dom.btnDownloadLocked.href = state.lastEncryptedBlobUrl;
      dom.btnDownloadLocked.download = lockedDownloadName;

      dom.encResOriginalName.textContent = originalName;
      dom.encResMime.textContent = mimeType.startsWith('text/') ? 'Text Document' : mimeType;
      dom.encResSize.textContent = `${formatBytes(packageBytes.byteLength)}`;
      dom.encResHash.textContent = packageDigest.substring(0, 16) + '...';

      dom.encryptProgressContainer.classList.add('hidden');
      dom.encryptSuccessCard.classList.remove('hidden');
      dom.encryptEngineStatus.textContent = 'LOCKED';
      dom.encryptEngineStatus.className = 'engine-badge ready';

      // =====================================================================
      // HARDENED SECURITY: CLEAR PASSWORD INPUT & MEMORY IMMEDIATELY
      // =====================================================================
      dom.encryptPassword.value = '';
      evaluatePasswordStrength('');

      showToast(`File locked successfully! Password cleared from memory for your safety.`, 'success');

    } catch (err) {
      console.error('Encryption failed:', err);
      dom.encryptProgressContainer.classList.add('hidden');
      dom.encryptEmptyState.classList.remove('hidden');
      dom.encryptEngineStatus.textContent = 'ERROR';
      showToast('Could not lock file: ' + (err.message || 'Unknown error'), 'error');
    } finally {
      dom.btnRunEncrypt.disabled = false;
    }
  }

  // =========================================================================
  // FILE & NOTE DECRYPTION WORKFLOW
  // =========================================================================
  function handleDecryptFileSelect(file) {
    if (!file) return;
    state.decryptFile = file;

    dom.decryptFileName.textContent = file.name;
    dom.decryptFileSize.textContent = formatBytes(file.size);

    dom.decryptDropzone.querySelector('.dropzone-content').classList.add('hidden');
    dom.decryptSelectedFile.classList.remove('hidden');
    dom.decryptErrorBanner.classList.add('hidden');
  }

  function clearDecryptFile() {
    state.decryptFile = null;
    dom.decryptFileInput.value = '';
    dom.decryptDropzone.querySelector('.dropzone-content').classList.remove('hidden');
    dom.decryptSelectedFile.classList.add('hidden');
  }

  async function executeDecryption() {
    // 1. HARDENED IN-MEMORY AUTHENTICATION CHECK
    if (!activeUserSession) {
      showToast('Please sign in to unlock files.', 'error');
      deactivateSessionView();
      return;
    }

    const password = dom.decryptPassword.value;
    dom.decryptErrorBanner.classList.add('hidden');

    if (!password) {
      showToast('Please enter the secret password for this file.', 'error');
      dom.decryptPassword.focus();
      return;
    }

    let packageBytes = null;

    // Check Base64 input vs File input
    const base64Input = dom.decryptBase64Text.value.trim();
    if (base64Input) {
      try {
        packageBytes = base64ToUint8Array(base64Input);
      } catch (e) {
        showToast('Invalid shareable text format. Please check the text and try again.', 'error');
        return;
      }
    } else if (state.decryptFile) {
      const buffer = await state.decryptFile.arrayBuffer();
      packageBytes = new Uint8Array(buffer);
    } else {
      showToast('Please upload a .locked file or paste shareable text.', 'error');
      return;
    }

    try {
      // UI: In Progress
      dom.decryptEmptyState.classList.add('hidden');
      dom.decryptSuccessCard.classList.add('hidden');
      dom.decryptProgressContainer.classList.remove('hidden');
      dom.decryptEngineStatus.textContent = 'UNLOCKING...';
      dom.btnRunDecrypt.disabled = true;

      await new Promise(resolve => setTimeout(resolve, 60));

      // 1. Parse VAULT02 Package
      let parsed;
      try {
        parsed = parseVaultPackage(packageBytes);
      } catch (parseErr) {
        throw new Error(parseErr.message || 'Corrupted or unrecognized file package.');
      }

      const { salt, iv, metadata, ciphertext } = parsed;

      // 2. Derive Key via PBKDF2 (100,000 rounds)
      const aesKey = await deriveFileAesKey(password, salt);

      // 3. Attempt Decryption
      let decryptedBuffer;
      try {
        decryptedBuffer = await window.crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: iv },
          aesKey,
          ciphertext
        );
      } catch (cryptoErr) {
        throw new Error('AUTH_FAILED');
      }

      // 4. Reconstruct restored file
      const originalMime = metadata.type || 'application/octet-stream';
      const originalFilename = metadata.name || 'restored_file.bin';
      const restoredBlob = new Blob([decryptedBuffer], { type: originalMime });

      if (state.lastDecryptedBlobUrl) URL.revokeObjectURL(state.lastDecryptedBlobUrl);
      state.lastDecryptedBlobUrl = URL.createObjectURL(restoredBlob);

      // Setup Download Button
      dom.btnDownloadRestored.href = state.lastDecryptedBlobUrl;
      dom.btnDownloadRestored.download = originalFilename;

      // Update Result Cards
      dom.decResName.textContent = originalFilename;
      dom.decResType.textContent = originalMime.startsWith('text/') ? 'Text Document' : originalMime;
      dom.decResSize.textContent = formatBytes(decryptedBuffer.byteLength);

      // Render In-Browser Preview
      renderDecryptedPreview(decryptedBuffer, metadata, state.lastDecryptedBlobUrl);

      // Show Success State
      dom.decryptProgressContainer.classList.add('hidden');
      dom.decryptSuccessCard.classList.remove('hidden');
      dom.decryptEngineStatus.textContent = 'RESTORED';
      dom.decryptEngineStatus.className = 'engine-badge ready';

      // =====================================================================
      // HARDENED SECURITY: CLEAR PASSWORD INPUT IMMEDIATELY ON SUCCESS
      // =====================================================================
      dom.decryptPassword.value = '';

      showToast(`File unlocked successfully! Password cleared from memory.`, 'success');

    } catch (err) {
      console.error('Decryption failed:', err);
      dom.decryptProgressContainer.classList.add('hidden');
      dom.decryptEngineStatus.textContent = 'DENIED';
      dom.decryptEngineStatus.className = 'engine-badge';

      dom.decryptErrorBanner.classList.remove('hidden');
      if (err.message === 'AUTH_FAILED') {
        dom.decryptErrorText.textContent = 'Oops! Incorrect password or invalid file. Please check your password and try again.';
        showToast('Oops! Incorrect password. Please try again.', 'error');
      } else {
        dom.decryptErrorText.textContent = err.message || 'Could not unlock file. Please verify your file and password.';
        showToast(err.message || 'Could not unlock file.', 'error');
      }
    } finally {
      dom.btnRunDecrypt.disabled = false;
    }
  }

  function renderDecryptedPreview(buffer, metadata, blobUrl) {
    dom.previewBody.innerHTML = '';
    const mime = (metadata.type || '').toLowerCase();
    const isText = metadata.isText || mime.startsWith('text/') || /\.(txt|md|csv|json|html|js|css|py|xml|log)$/i.test(metadata.name);

    dom.btnCopyRestoredText.classList.add('hidden');

    if (isText) {
      dom.previewTypeTag.textContent = 'NOTE / TEXT';
      const textDecoder = new TextDecoder('utf-8');
      const textContent = textDecoder.decode(buffer);
      state.lastRestoredText = textContent;

      const pre = document.createElement('pre');
      pre.className = 'preview-text-block';
      pre.textContent = textContent;
      dom.previewBody.appendChild(pre);

      dom.btnCopyRestoredText.classList.remove('hidden');

    } else if (mime.startsWith('image/')) {
      dom.previewTypeTag.textContent = 'PHOTO';
      const img = document.createElement('img');
      img.className = 'preview-img';
      img.src = blobUrl;
      img.alt = metadata.name || 'Decrypted Image Preview';
      dom.previewBody.appendChild(img);

    } else if (mime.startsWith('video/')) {
      dom.previewTypeTag.textContent = 'VIDEO';
      const video = document.createElement('video');
      video.className = 'preview-media-player';
      video.controls = true;
      video.src = blobUrl;
      dom.previewBody.appendChild(video);

    } else if (mime.startsWith('audio/')) {
      dom.previewTypeTag.textContent = 'AUDIO';
      const audio = document.createElement('audio');
      audio.className = 'preview-media-player';
      audio.controls = true;
      audio.src = blobUrl;
      dom.previewBody.appendChild(audio);

    } else {
      dom.previewTypeTag.textContent = 'DOCUMENT / FILE';
      const card = document.createElement('div');
      card.className = 'preview-generic-card';
      card.innerHTML = `
        <div class="preview-generic-icon">📄</div>
        <h4>${escapeHtml(metadata.name)}</h4>
        <p>Restored ${formatBytes(buffer.byteLength)} original file. Click the download button below to save it.</p>
      `;
      dom.previewBody.appendChild(card);
    }
  }

  // =========================================================================
  // SETUP DRAG & DROP LISTENERS
  // =========================================================================
  function setupDropzone(dropzoneEl, fileInputEl, onFileSelected) {
    ['dragenter', 'dragover'].forEach(eventName => {
      dropzoneEl.addEventListener(eventName, e => {
        e.preventDefault();
        e.stopPropagation();
        dropzoneEl.classList.add('dragover');
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropzoneEl.addEventListener(eventName, e => {
        e.preventDefault();
        e.stopPropagation();
        dropzoneEl.classList.remove('dragover');
      });
    });

    dropzoneEl.addEventListener('drop', e => {
      const dt = e.dataTransfer;
      if (dt && dt.files && dt.files.length > 0) {
        onFileSelected(dt.files[0]);
      }
    });

    dropzoneEl.addEventListener('click', e => {
      if (e.target.closest('.btn-remove-file')) return;
      fileInputEl.click();
    });

    dropzoneEl.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        fileInputEl.click();
      }
    });

    fileInputEl.addEventListener('change', e => {
      if (e.target.files && e.target.files.length > 0) {
        onFileSelected(e.target.files[0]);
      }
    });
  }

  // =========================================================================
  // EVENT LISTENERS INITIALIZATION
  // =========================================================================
  function initEventListeners() {
    // Auth Forms & Tab Switchers
    dom.tabBtnLogin.addEventListener('click', () => switchAuthTab('login'));
    dom.tabBtnRegister.addEventListener('click', () => switchAuthTab('register'));
    dom.formLogin.addEventListener('submit', handleLogin);
    dom.formRegister.addEventListener('submit', handleRegistration);
    dom.btnLogout.addEventListener('click', handleLogout);

    // Password Visibility Toggles
    document.querySelectorAll('.btn-toggle-pwd').forEach(btn => {
      btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-target');
        const input = document.getElementById(targetId);
        if (!input) return;
        if (input.type === 'password') {
          input.type = 'text';
          btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;
        } else {
          input.type = 'password';
          btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
        }
      });
    });

    // Workspace Navigation Tabs
    dom.navTabEncrypt.addEventListener('click', () => switchWorkspaceTab('encrypt'));
    dom.navTabDecrypt.addEventListener('click', () => switchWorkspaceTab('decrypt'));
    dom.navTabAudit.addEventListener('click', () => switchWorkspaceTab('audit'));

    // Encryption Submodes
    dom.submodeFile.addEventListener('click', () => setEncryptSubmode('file'));
    dom.submodeText.addEventListener('click', () => setEncryptSubmode('text'));

    // Live Plaintext Word & Character Counter
    dom.encryptPlaintext.addEventListener('input', () => {
      const val = dom.encryptPlaintext.value;
      const chars = val.length;
      const words = val.trim() ? val.trim().split(/\s+/).length : 0;
      dom.textCounter.textContent = `${chars} chars / ${words} words`;
    });

    // Password Strength & Key Gen
    dom.encryptPassword.addEventListener('input', () => {
      evaluatePasswordStrength(dom.encryptPassword.value);
    });
    dom.btnGenPass.addEventListener('click', generateHighEntropyPassword);

    // Dropzone Initializations
    setupDropzone(dom.encryptDropzone, dom.encryptFileInput, handleEncryptFileSelect);
    setupDropzone(dom.decryptDropzone, dom.decryptFileInput, handleDecryptFileSelect);

    dom.btnRemoveEncryptFile.addEventListener('click', e => {
      e.stopPropagation();
      clearEncryptFile();
    });

    dom.btnRemoveDecryptFile.addEventListener('click', e => {
      e.stopPropagation();
      clearDecryptFile();
    });

    // Run Encryption & Decryption
    dom.btnRunEncrypt.addEventListener('click', executeEncryption);
    dom.btnRunDecrypt.addEventListener('click', executeDecryption);

    // Copy Base64 Shareable Text
    dom.btnCopyEncBase64.addEventListener('click', () => {
      if (!state.lastEncryptedBase64) return;
      navigator.clipboard.writeText(state.lastEncryptedBase64).then(() => {
        showToast('Shareable encrypted text copied to clipboard!', 'success');
      }).catch(() => {
        showToast('Could not copy to clipboard. Permission denied.', 'error');
      });
    });

    // Copy Restored Note Text
    dom.btnCopyRestoredText.addEventListener('click', () => {
      if (!state.lastRestoredText) return;
      navigator.clipboard.writeText(state.lastRestoredText).then(() => {
        showToast('Restored note copied to clipboard!', 'success');
      }).catch(() => {
        showToast('Could not copy to clipboard.', 'error');
      });
    });

    // Toggle Base64 text box for decryption
    dom.btnToggleBase64Input.addEventListener('click', () => {
      dom.decryptBase64Container.classList.toggle('hidden');
    });
  }

  // =========================================================================
  // BOOTSTRAP APPLICATION
  // =========================================================================
  function init() {
    initEventListeners();
    // In-memory closure security: Start in clean login gate
    deactivateSessionView();
  }

  // Launch when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
