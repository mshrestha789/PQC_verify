# 🔐 Kyber + Dilithium Verification and Extraction (C DLL for C# Integration)

This project provides a C implementation to:

* ✅ **Verify** a Dilithium digital signature on a hex-encoded message.
* 🔓 **Decapsulate** a Kyber shared secret using ciphertext embedded in the message.
* 📦 **Extract** the ChaCha20-Poly1305 `nonce`, `tag`, and encrypted `ciphertext` from the message.
* 🧹 Designed to be compiled into a **DLL** for use in C# via **P/Invoke**.

---

## 🚀 Function: `verify_and_extract(...)`

### Signature

```c
int verify_and_extract(
    const char* msg_hex,
    const char* pk_hex,
    const char* sig_hex,
    uint8_t* out_ss,              // [out] 32 bytes (Kyber shared secret)
    uint8_t* out_nonce,           // [out] 12 bytes (ChaCha20 nonce)
    uint8_t* out_tag,             // [out] 16 bytes (Poly1305 tag)
    uint8_t* out_ciphertext,      // [out] variable-length payload
    size_t* out_ciphertext_len    // [out] length of ciphertext
);
```

### Parameters

* `msg_hex`: Full hex string containing:

  * \[0–799] → Kyber Ciphertext (800 bytes)
  * \[800–811] → ChaCha20 Nonce (12 bytes)
  * \[812–827] → Poly1305 Tag (16 bytes)
  * \[828–end] → Encrypted data (ciphertext)
* `pk_hex`: Sender's Dilithium public key (hex-encoded)
* `sig_hex`: Dilithium signature (hex-encoded)

### Outputs

* `out_ss`: 32-byte shared secret (Kyber decapsulation output)
* `out_nonce`: 12-byte nonce extracted from message
* `out_tag`: 16-byte tag
* `out_ciphertext`: Raw ciphertext buffer
* `out_ciphertext_len`: Length of ciphertext extracted

---

## 📁 Secret Key Requirement

This function reads the Kyber **secret key** from a binary file named:

```
kyber_sk.bin
```

Make sure the file is available in the same directory as the DLL or executable using it.

---

## 🧪 Testing (Standalone)

For standalone testing (without C#), a backup file named `verify_extract.c` is provided with a `main()` function and hardcoded test values.

* This is disabled using:

```c
#if 0
int main() {
    ...
}
#endif
```

* You can re-enable the test code by changing `#if 0` → `#if 1`.

---

## ❌ Error Codes

| Return Code | Meaning                           |
| ----------- | --------------------------------- |
| `0`         | ✅ Success                         |
| `-1`        | ❌ Message too short               |
| `-2`        | ❌ Memory allocation failed        |
| `-3`        | ❌ Signature verification failed   |
| `-4`        | ❌ Failed to load Kyber secret key |
| `-5`        | ❌ Kyber decapsulation failed      |

---

## 📆 Build Instructions (Visual Studio)

### 📗 Option 1: Build as DLL (For C# Integration)

1. **Open Visual Studio**

   * Use Visual Studio 2022 or later
   * Ensure **Desktop Development with C++** workload is installed

2. **Create a New Project**

   * Template: **Console App** (C++)
   * Name: `VerifyExtract`

3. **Change to DLL Output**

   * Right-click your project → **Properties**
   * Go to `Configuration Properties → General`
   * Set **Configuration Type** to `Dynamic Library (.dll)`

4. **Add Source Files**

   * Right-click project → *Add* → *Existing Item...*
   * Add:

     * `verify_extract.c`
     * `params.h`, `sign.h`, `kyber_api.h`, and other required files from Dilithium/Kyber

5. **Define DLL Export Macro** *(optional)*

   * Project Properties → `C/C++` → `Preprocessor`
   * Add: `DLL_EXPORT`

6. **Build**

   * Press **Ctrl + Shift + B** to build the DLL
   * Output will be in `Debug/` or `Release/` folder

### 📘 Option 2: Build as EXE for Local Testing

If you want to run the code as a console app, enable the `main()` function in `verify_extract.c` and set:

* Project → Properties → `Configuration Type` → `Application (.exe)`

---

## 🤝 C# Integration Example

```csharp
[DllImport("verify_extract.dll", CallingConvention = CallingConvention.Cdecl)]
public static extern int verify_and_extract(
    string msg_hex, string pk_hex, string sig_hex,
    byte[] out_ss, byte[] out_nonce, byte[] out_tag,
    byte[] out_ciphertext, ref UIntPtr out_ciphertext_len);
```

---

## 📆 Dependencies

This project uses official reference implementations from the [pq-crystals](https://pq-crystals.org/) project:

* ✅ `sign.h`, `params.h`, `sign.c`, etc. → from **Dilithium**
* ✅ `kyber_api.h`, `kyber_*.c/.h`, etc. → from **Kyber512**
* Ensure these are included properly in your Visual Studio project.

---

## 🧑‍💻 Author

Designed for integrating Kyber + Dilithium-based secure message extraction in embedded and .NET systems.

---
