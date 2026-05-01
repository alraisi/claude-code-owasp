---
name: owasp-mobile-security
description: Use when building, reviewing, or testing any mobile application (Android, iOS, cross-platform like Flutter/React Native, hybrid, or SDK). Covers OWASP MASVS v2.1.0 (Mobile Application Security Verification Standard) and MASTG v1.7.0 (Mobile Application Security Testing Guide). All 8 control groups: STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE, PRIVACY. Includes Android (Kotlin) and iOS (Swift) secure code patterns, certificate pinning, root/jailbreak detection, anti-tampering, and MASTG testing methodology with Frida/Objection. For backend security use owasp-web-security.
---

# OWASP MAS — Mobile Application Security (MASVS v2.1.0 + MASTG v1.7.0)

Apply these standards when building, reviewing, or testing any mobile application — Android, iOS, cross-platform (Flutter, React Native, Xamarin), hybrid (Cordova), or SDK. The **MASVS** defines *what* must be secured; the **MASTG** defines *how* to test it.

> **Scope:** MASVS covers the mobile client only. Backend endpoints must be verified separately against OWASP ASVS (use the **owasp-web-security** skill).

---

## MASVS Control Groups — Quick Reference

| Group | Focus | Controls |
|-------|-------|----------|
| **MASVS-STORAGE** | Sensitive data at rest | STORAGE-1, STORAGE-2 |
| **MASVS-CRYPTO** | Cryptographic implementation & key management | CRYPTO-1, CRYPTO-2 |
| **MASVS-AUTH** | Authentication & authorization protocols | AUTH-1, AUTH-2, AUTH-3 |
| **MASVS-NETWORK** | Secure network communication & certificate pinning | NETWORK-1, NETWORK-2 |
| **MASVS-PLATFORM** | IPC, WebViews, UI security | PLATFORM-1, PLATFORM-2, PLATFORM-3 |
| **MASVS-CODE** | Code quality, dependency management, input validation | CODE-1, CODE-2, CODE-3, CODE-4 |
| **MASVS-RESILIENCE** | Anti-tampering, anti-reversing, runtime integrity | RESILIENCE-1, RESILIENCE-2, RESILIENCE-3, RESILIENCE-4 |
| **MASVS-PRIVACY** | Data minimization, user identity protection, transparency | PRIVACY-1, PRIVACY-2, PRIVACY-3, PRIVACY-4 |

---

## MASVS-STORAGE: Sensitive Data at Rest

**STORAGE-1 — The app securely stores sensitive data.**

Sensitive data (PII, tokens, credentials, keys) intentionally stored by the app must be protected regardless of location — internal storage, shared preferences, SQLite, or external storage.

**STORAGE-2 — The app prevents leakage of sensitive data.**

Data must not be unintentionally exposed through logs, backups, screenshots, clipboard, auto-fill caches, or third-party keyboard access.

**Android — Secure Storage Patterns:**
```kotlin
// UNSAFE: Plaintext SharedPreferences
getSharedPreferences("prefs", MODE_PRIVATE)
    .edit().putString("token", authToken).apply()

// SAFE: EncryptedSharedPreferences (Jetpack Security)
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
val prefs = EncryptedSharedPreferences.create(
    context, "secure_prefs", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

// SAFE: Android Keystore for cryptographic keys
val keyGen = KeyPairGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
keyGen.initialize(KeyGenParameterSpec.Builder(
    "my_key_alias",
    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
    .setDigests(KeyProperties.DIGEST_SHA256).build())
```

**iOS — Secure Storage Patterns:**
```swift
// UNSAFE: UserDefaults for sensitive data
UserDefaults.standard.set(authToken, forKey: "token")

// SAFE: Keychain with appropriate accessibility
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "auth_token",
    kSecValueData as String: tokenData,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
]
SecItemAdd(query as CFDictionary, nil)

// SAFE: Exclude sensitive files from iCloud backup
var url = URL(fileURLWithPath: sensitiveFilePath)
try url.setResourceValue(true, forKey: .isExcludedFromBackupKey)
```

**Key MASTG Testing Checks:**
- [ ] No credentials, tokens, or keys stored in plaintext SharedPreferences / UserDefaults
- [ ] No sensitive data written to application logs (`Log.d`, `NSLog`, `print`)
- [ ] Sensitive files excluded from backups (iOS: `NSURLIsExcludedFromBackupKey`; Android: `android:allowBackup="false"`)
- [ ] No sensitive data in SQLite databases without encryption (SQLCipher where needed)
- [ ] Keyboard cache disabled for sensitive input fields (`android:inputType="textNoSuggestions"` / `UITextSmartQuotesType.no`)
- [ ] Screenshots disabled for sensitive screens (`FLAG_SECURE` / `ignoresKeyboardDismissalRequests`)
- [ ] Clipboard access restricted for password fields

---

## MASVS-CRYPTO: Cryptography

**CRYPTO-1 — The app employs current strong cryptography according to industry best practices.**

No custom cryptography. No deprecated algorithms. Use platform-standard APIs only.

**CRYPTO-2 — The app performs key management according to industry best practices.**

Keys generated, stored, and protected using hardware-backed keystores where available.

**Forbidden Algorithms (MASTG):**

| Category | UNSAFE | SAFE Replacement |
|----------|--------|-----------------|
| Symmetric encryption | DES, 3DES, RC2, RC4, Blowfish | AES-256-GCM or AES-256-CBC |
| Hashing | MD4, MD5, SHA-1 | SHA-256, SHA-3 |
| Asymmetric | RSA < 2048-bit | RSA-2048+, ECDSA P-256+ |
| Random number generation | `java.util.Random`, `Math.random()`, `rand()` | `SecureRandom`, `SecRandomCopyBytes` |
| Key derivation | Direct key from password | PBKDF2, Argon2, bcrypt |

```kotlin
// UNSAFE: ECB mode (identical plaintext → identical ciphertext)
val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")

// SAFE: GCM mode with random IV (provides authenticity + confidentiality)
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, iv))

// UNSAFE: Hardcoded key
val key = "0123456789abcdef".toByteArray()

// SAFE: Key from Android Keystore (hardware-backed on supported devices)
val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
val secretKey = keyStore.getKey("my_aes_key", null) as SecretKey
```

**Key MASTG Testing Checks:**
- [ ] No hardcoded keys, IVs, or seeds in source code or compiled binary
- [ ] No use of ECB mode for block cipher encryption
- [ ] IVs/nonces are unique and randomly generated per encryption operation
- [ ] Keys stored in Android Keystore / iOS Secure Enclave, not in SharedPreferences or files
- [ ] Custom cryptographic implementations absent — only platform APIs used
- [ ] Key size meets minimum: AES ≥ 128-bit (256 preferred), RSA ≥ 2048-bit, ECC ≥ 224-bit

---

## MASVS-AUTH: Authentication & Authorization

**AUTH-1 — The app uses secure authentication and authorization protocols and follows relevant best practices.**

OAuth 2.0 / OIDC flows implemented correctly; tokens validated server-side on every request.

**AUTH-2 — The app performs local authentication securely according to platform best practices.**

Biometric and PIN authentication must use platform APIs tied to the Keystore/Secure Enclave — not client-side comparisons.

**AUTH-3 — The app secures sensitive operations with additional authentication.**

Step-up authentication (biometric, MFA, re-entry of PIN) required for high-value actions (payments, account changes).

```kotlin
// UNSAFE: Custom biometric check bypasses hardware binding
if (fingerprintMatch(storedTemplate, scannedTemplate)) { grantAccess() }

// SAFE: BiometricPrompt with CryptoObject — hardware-bound
val biometricPrompt = BiometricPrompt(activity, executor,
    object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            // result.cryptoObject.cipher is now unlocked by hardware auth
            val cipher = result.cryptoObject?.cipher!!
            val decryptedToken = cipher.doFinal(encryptedToken)
        }
    })
val promptInfo = BiometricPrompt.PromptInfo.Builder()
    .setTitle("Authenticate")
    .setNegativeButtonText("Cancel")
    .build()
biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
```

**Key MASTG Testing Checks:**
- [ ] Authentication enforced server-side on all sensitive endpoints — not just client-side
- [ ] JWTs validated: algorithm not "none", signature verified, expiry checked
- [ ] OAuth: PKCE used for public clients; `state` parameter prevents CSRF; redirect URIs validated
- [ ] Biometric authentication uses `CryptoObject` (Android) or `LAContext` with Keychain (iOS) — not raw biometric comparison
- [ ] Session tokens invalidated on logout server-side
- [ ] Sensitive operations (payments, account changes) require step-up authentication

---

## MASVS-NETWORK: Network Communication

**NETWORK-1 — The app secures all network traffic according to current best practices.**

TLS 1.2+ enforced. No plaintext HTTP. Platform secure defaults not overridden.

**NETWORK-2 — The app performs identity pinning for all remote endpoints under the developer's control.**

Certificate or public key pinning for sensitive endpoints to prevent MITM even if a CA is compromised.

```kotlin
// UNSAFE: Trust all certificates (disables TLS verification entirely)
val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
})

// SAFE: OkHttp Certificate Pinning
val client = OkHttpClient.Builder()
    .certificatePinner(
        CertificatePinner.Builder()
            .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .add("api.example.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=") // backup pin
            .build()
    ).build()
```

```swift
// iOS: Network Security with certificate pinning via URLSession delegate
func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    guard let serverCert = challenge.protectionSpace.serverTrust,
          let remoteCertData = SecCertificateCopyData(SecTrustGetCertificateAtIndex(serverCert, 0)!) as Data?,
          let localCertData = NSData(contentsOfFile: Bundle.main.path(forResource: "cert", ofType: "cer")!) as Data?,
          remoteCertData == localCertData else {
        completionHandler(.cancelAuthenticationChallenge, nil)
        return
    }
    completionHandler(.useCredential, URLCredential(trust: serverCert))
}
```

**Key MASTG Testing Checks:**
- [ ] TLS 1.2+ enforced; TLS 1.0/1.1 and SSLv3 disabled
- [ ] No `allowsArbitraryLoads = true` in iOS ATS without justification
- [ ] No `android:usesCleartextTraffic="true"` for sensitive connections
- [ ] Certificate pinning implemented with at least 2 pins (primary + backup)
- [ ] No custom `TrustManager` that accepts all certificates
- [ ] No custom `HostnameVerifier` that returns `true` for all hosts
- [ ] Proxy detection does not bypass security controls

---

## MASVS-PLATFORM: Platform Interaction

**PLATFORM-1 — The app uses IPC mechanisms securely.**

Intents, content providers, broadcast receivers, and URL schemes must not expose sensitive data or functionality to unauthorized apps.

**PLATFORM-2 — The app uses WebViews securely.**

JavaScript interfaces, `file://` access, and universal link handling must be tightly controlled.

**PLATFORM-3 — The app uses the user interface securely.**

Sensitive data not leaked through screenshots, notifications, auto-fill, or shoulder surfing.

```kotlin
// UNSAFE: Exported activity accepts arbitrary intents from any app
<activity android:name=".SensitiveActivity" android:exported="true" />

// SAFE: Restrict with permissions or remove export
<activity android:name=".SensitiveActivity"
          android:exported="false" />  // or with permission:
<activity android:name=".SensitiveActivity"
          android:exported="true"
          android:permission="com.example.LAUNCH_SENSITIVE" />

// UNSAFE: WebView with JavaScript interface exposed to all origins
webView.addJavascriptInterface(myObject, "Android")
webView.settings.javaScriptEnabled = true
webView.loadUrl("https://untrusted.site.com")

// SAFE: Restrict JS interface to trusted origins, disable file access
webView.settings.apply {
    javaScriptEnabled = true  // only if necessary
    allowFileAccess = false
    allowContentAccess = false
    allowUniversalAccessFromFileURLs = false
}
// Only add JS interface when loading trusted, controlled URLs
```

**Key MASTG Testing Checks:**
- [ ] No unnecessarily exported Activities, Services, Content Providers, or Broadcast Receivers
- [ ] Deep links and custom URL schemes validated — cannot be hijacked by other apps
- [ ] WebView: `setAllowFileAccessFromFileURLs(false)`, `setAllowUniversalAccessFromFileURLs(false)`
- [ ] JavaScript interfaces only exposed when loading trusted content
- [ ] Sensitive text fields: `inputType` set to suppress autocomplete and keyboard cache
- [ ] `FLAG_SECURE` set on Activities displaying sensitive data (prevents screenshots)
- [ ] Sensitive data redacted in iOS app switcher snapshot (use `UIImageView` overlay on `applicationWillResignActive`)
- [ ] Push notifications do not expose sensitive data in notification payload

---

## MASVS-CODE: Code Quality

**CODE-1 — The app requires an up-to-date platform version.** (Minimum target SDK / iOS version enforced)

**CODE-2 — The app has a mechanism for enforcing app updates.** (Force update for critical security fixes)

**CODE-3 — The app only uses software components without known vulnerabilities.** (Dependency scanning)

**CODE-4 — The app validates and sanitizes all untrusted inputs.** (All data entry points: UI, IPC, network, files)

```kotlin
// UNSAFE: Raw query from user input — SQL injection
val cursor = db.rawQuery("SELECT * FROM users WHERE name = '$input'", null)

// SAFE: Parameterized query
val cursor = db.rawQuery("SELECT * FROM users WHERE name = ?", arrayOf(input))

// UNSAFE: Evaluating user-supplied JavaScript in WebView
webView.evaluateJavascript("processData('$userInput')", null)

// SAFE: Sanitize before injection, or use postMessage instead
val safeInput = userInput.replace("'", "\\'").replace("\"", "\\\"")
```

**Binary Protection — What MASTG Tests For:**
- **PIE (Position Independent Executable):** Must be enabled → enables ASLR
- **Stack canaries:** Must be enabled → detects stack buffer overflows
- **ARC / SafeStack:** Automatic Reference Counting or stack protection
- **Symbol stripping:** Release builds should strip debug symbols

```bash
# Check Android binary protections
apktool d app.apk
# Check for minSdkVersion, targetSdkVersion in AndroidManifest.xml

# Check iOS binary protections with otool
otool -hv MyApp  # check PIE flag
otool -Iv MyApp | grep stack_chk  # check stack canaries
```

**Key MASTG Testing Checks:**
- [ ] `minSdkVersion` ≥ Android 8.0 (API 26) / iOS 14 or justified exception
- [ ] Force-update mechanism present for critical patches
- [ ] All third-party dependencies scanned for CVEs (OWASP Dependency-Check, Snyk)
- [ ] All user input validated and sanitized before use in queries, commands, or rendering
- [ ] No hardcoded credentials, API keys, or secrets in source code or compiled binary
- [ ] PIE and stack canaries enabled in release builds
- [ ] No debug code in production (`BuildConfig.DEBUG` guarded, `android:debuggable="false"`)
- [ ] `StrictMode` violations resolved; no sensitive data in HTTP traffic during testing

---

## MASVS-RESILIENCE: Anti-Tampering & Anti-Reversing

> **Important:** Resilience controls are **defense-in-depth** — they increase attacker effort but cannot be a substitute for other security controls. The reverse engineer always wins eventually.

**RESILIENCE-1 — The app validates the integrity of the platform.**

Detect rooted (Android) / jailbroken (iOS) devices and respond appropriately for high-risk applications.

**RESILIENCE-2 — The app implements anti-tampering mechanisms.**

Detect modification of the app binary, resources, or signature at runtime.

**RESILIENCE-3 — The app implements anti-static analysis mechanisms.**

Code obfuscation, string encryption, control flow obfuscation to impede reverse engineering.

**RESILIENCE-4 — The app implements anti-dynamic analysis techniques.**

Debugger detection, emulator detection, Frida/Substrate/Xposed detection for high-security apps.

```kotlin
// Root detection (Android) — multiple checks needed; single checks are easily bypassed
object RootDetector {
    fun isRooted(): Boolean {
        return checkSuBinary() || checkBuildTags() || checkDangerousProps() || checkRWPaths()
    }

    private fun checkSuBinary(): Boolean {
        val paths = arrayOf("/system/bin/su", "/system/xbin/su", "/sbin/su")
        return paths.any { File(it).exists() }
    }

    private fun checkBuildTags(): Boolean {
        return Build.TAGS?.contains("test-keys") == true
    }
}

// IMPORTANT: Always layer root detection with server-side validation
// and use commercial SDKs (e.g., SafetyNet/Play Integrity API) for production
```

**Obfuscation Techniques (MASTG):**
- **Name obfuscation:** R8/ProGuard for Android; Swift symbol stripping for iOS
- **String encryption:** Encrypt sensitive strings, decrypt at runtime
- **Control flow flattening:** Transforms natural conditional logic into state machine
- **Dead code injection:** Adds fake code paths to confuse static analysis
- **Packing:** Compress/encrypt binary, decompress at runtime

```groovy
// Android: Enable R8 full mode obfuscation in build.gradle
android {
    buildTypes {
        release {
            minifyEnabled true
            shrinkResources true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'),
                         'proguard-rules.pro'
        }
    }
}
```

**Key MASTG Testing Checks:**
- [ ] Root/jailbreak detection implemented and tested with bypass tools (Magisk, Frida)
- [ ] App signature verification at runtime detects repackaging
- [ ] R8/ProGuard obfuscation enabled in release builds (Android)
- [ ] Debug symbols stripped from release builds (iOS: `STRIP_SWIFT_SYMBOLS = YES`)
- [ ] Frida, Cydia Substrate, and Xposed detection for high-security apps
- [ ] Emulator detection where appropriate (check for emulator-specific files, properties)
- [ ] Anti-tampering controls assessed for bypass-resistance — test with Frida, Objection, APKTool

---

## MASVS-PRIVACY: User Privacy

**PRIVACY-1 — The app minimizes access to sensitive data and resources.**

Request only permissions actually needed. Third-party SDKs must not collect data beyond user consent.

**PRIVACY-2 — The app prevents identification of the user.**

Use anonymization, pseudonymization, and data abstraction. Isolate fingerprint signals by purpose.

**PRIVACY-3 — The app is transparent about data collection and usage.**

Privacy policy accurately describes all data collected. App store privacy labels (Google Data Safety / Apple Nutrition Labels) must be accurate.

**PRIVACY-4 — The app offers user control over their data.**

Users can view, modify, delete their data and revoke consent at any time.

```kotlin
// UNSAFE: Request permissions at startup without context
override fun onCreate(...) {
    requestPermissions(arrayOf(Manifest.permission.READ_CONTACTS,
                               Manifest.permission.CAMERA,
                               Manifest.permission.ACCESS_FINE_LOCATION), 0)
}

// SAFE: Request permissions contextually, only when needed, with rationale
fun capturePhoto() {
    if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
            != PackageManager.PERMISSION_GRANTED) {
        if (shouldShowRequestPermissionRationale(Manifest.permission.CAMERA)) {
            showRationaleDialog("Camera access is needed to take photos")
        } else {
            requestPermissions(arrayOf(Manifest.permission.CAMERA), CAMERA_REQUEST)
        }
    } else {
        launchCamera()
    }
}
```

**Key MASTG Testing Checks:**
- [ ] Only necessary permissions requested; no unused permissions in manifest
- [ ] Location: use `ACCESS_COARSE_LOCATION` instead of `ACCESS_FINE_LOCATION` where precision is unnecessary
- [ ] Background location access justified and disclosed
- [ ] Analytics and advertising SDKs respect opt-out signals and user consent
- [ ] No device fingerprinting across apps without explicit consent (IDFA/GAID gated on permission)
- [ ] Privacy policy URL present and content matches actual app behavior
- [ ] Google Data Safety section / Apple App Privacy labels accurate
- [ ] Users can delete account and associated data from within the app

---

## MASTG Testing Methodology

The MASTG defines a structured testing approach for both **black-box** (no source) and **white-box** (full source) assessments.

### Testing Setup

**Android:**
```bash
# Install testing tools
adb install app.apk
adb shell pm list packages | grep target

# Extract APK for static analysis
adb shell pm path com.example.app
adb pull /data/app/com.example.app-1/base.apk

# Decompile with apktool (smali)
apktool d base.apk -o output/

# Decompile to Java with jadx
jadx -d output/ base.apk

# Dynamic analysis with Frida
frida-ps -U  # list processes on USB device
frida -U -l my_script.js -f com.example.app --no-pause
```

**iOS:**
```bash
# Install on jailbroken device via Cydia/Sileo
# Or use Corellium for non-jailbroken testing

# Decrypt IPA (on jailbroken device)
frida-ios-dump com.example.app

# Static analysis
class-dump -H MyApp -o headers/
otool -L MyApp  # list linked libraries
strings MyApp | grep -i "password\|secret\|key\|token"

# Dynamic analysis with Objection (Frida-based)
objection -g com.example.app explore
```

### Key Testing Techniques (MASTG)

**Intercepting HTTPS Traffic:**
```bash
# Set up Burp Suite proxy, install CA cert on device
# Android 7+: Add network_security_config.xml for debug builds
# <network-security-config>
#   <debug-overrides>
#     <trust-anchors>
#       <certificates src="user" />
#     </trust-anchors>
#   </debug-overrides>
# </network-security-config>

# Bypass certificate pinning with Frida
frida -U -l ssl_pinning_bypass.js -f com.example.app
```

**Reverse Engineering & Binary Analysis:**
```bash
# Check binary protections
checksec --file=libnative.so  # Linux/Android native libraries
# Look for: NX, PIE, Canary, RELRO, FORTIFY

# Disassemble with Ghidra or radare2
r2 -A libnative.so
afl  # list all functions
pdf @ sym.check_license  # disassemble function
```

**Runtime Manipulation with Frida:**
```javascript
// Hook a method to bypass root detection
Java.perform(function() {
    var RootDetector = Java.use("com.example.security.RootDetector");
    RootDetector.isRooted.implementation = function() {
        console.log("[*] isRooted() called — returning false");
        return false;
    };
});

// Dump decrypted strings at runtime
Interceptor.attach(Module.findExportByName(null, "CCCrypt"), {
    onEnter: function(args) {
        console.log("[*] CCCrypt called, key: " + args[6].readUtf8String());
    }
});
```

---

## Mobile Security Review Checklist

Use this combined MASVS + MASTG checklist for any mobile security assessment:

**Storage (MASVS-STORAGE)**
- [ ] No sensitive data in SharedPreferences/UserDefaults without encryption
- [ ] No sensitive data in application logs
- [ ] Backups excluded or encrypted for sensitive data
- [ ] SQLite databases encrypted where containing sensitive data
- [ ] No sensitive data in app cache, temp files, or crash logs

**Cryptography (MASVS-CRYPTO)**
- [ ] No deprecated algorithms (DES, 3DES, RC4, MD5, SHA-1)
- [ ] No hardcoded keys, IVs, or passwords
- [ ] No ECB mode; GCM or CBC with random IV used
- [ ] Keys stored in Android Keystore / iOS Secure Enclave
- [ ] No custom cryptographic implementations

**Authentication (MASVS-AUTH)**
- [ ] All auth enforced server-side; no client-side-only bypass possible
- [ ] JWT tokens: algorithm validated, signature verified, expiry checked
- [ ] OAuth/OIDC: PKCE, state parameter, redirect URI validation
- [ ] Biometric auth hardware-bound (CryptoObject / Keychain)
- [ ] Session tokens invalidated server-side on logout

**Network (MASVS-NETWORK)**
- [ ] TLS 1.2+ only; no cleartext traffic for sensitive connections
- [ ] No permissive TrustManager or HostnameVerifier
- [ ] Certificate pinning with 2+ pins for sensitive endpoints
- [ ] ATS not disabled globally on iOS

**Platform (MASVS-PLATFORM)**
- [ ] No unnecessarily exported components (activities, services, receivers)
- [ ] Deep links and custom schemes validated
- [ ] WebView: no dangerous settings enabled (`allowFileAccess`, JS bridges to untrusted content)
- [ ] Sensitive screens use FLAG_SECURE / app switcher snapshot protection

**Code Quality (MASVS-CODE)**
- [ ] Minimum supported OS version enforced
- [ ] All dependencies scanned for known CVEs
- [ ] All user input validated and sanitized
- [ ] No hardcoded secrets in source or binary
- [ ] PIE and stack canaries enabled; debug mode off in release

**Resilience (MASVS-RESILIENCE)**
- [ ] Root/jailbreak detection appropriate to app risk level
- [ ] R8/ProGuard obfuscation enabled for Android release builds
- [ ] Anti-tampering (signature check) in place for high-security apps
- [ ] Anti-debugging/Frida detection for high-security apps

**Privacy (MASVS-PRIVACY)**
- [ ] Only necessary permissions requested; permission rationale shown
- [ ] Third-party SDKs comply with user consent signals
- [ ] Privacy policy accurate; app store labels accurate
- [ ] User data deletion mechanism available in-app

---

## When to Apply This Skill

- Building, reviewing, or testing any Android or iOS application
- Cross-platform mobile development (Flutter, React Native, Xamarin, Ionic)
- Hybrid mobile apps (Cordova, PhoneGap)
- Mobile SDK development
- Mobile penetration testing or security assessment
- Mobile app threat modeling

For backend security or REST API security, use **owasp-web-security**. For LLM-powered mobile features, also use **owasp-llm-security**.
