---
name: owasp-language-quirks
description: Use when reviewing or writing code in any specific programming language to apply language-specific security patterns and avoid known footguns. Covers JavaScript/TypeScript, Python, Java, Go, PHP, C#/.NET, Ruby, Rust, Swift, Kotlin, C/C++, Scala, R, Perl, Shell/Bash, Lua, Elixir, Dart/Flutter, PowerShell, and SQL. Pairs well with owasp-web-security for web apps, owasp-mobile-security for mobile, or owasp-llm-security for LLM apps. Includes a deep security analysis mindset for languages not explicitly listed.
---

# Language-Specific Security Quirks

> Think like a senior security researcher: consider memory model, type system, serialization, concurrency, FFI boundaries, stdlib CVE history, and package ecosystem risks. The examples below are starting points, not exhaustive.

---

## JavaScript / TypeScript
**Main Risks:** Prototype pollution, XSS, eval injection
```javascript
// UNSAFE: Prototype pollution
Object.assign(target, userInput)
// SAFE: Use null prototype or validate keys
Object.assign(Object.create(null), validated)

// UNSAFE: eval injection
eval(userCode)
// SAFE: Never use eval with user input
```
**Watch for:** `eval()`, `innerHTML`, `document.write()`, prototype chain manipulation, `__proto__`

---

## Python
**Main Risks:** Pickle deserialization, format string injection, shell injection
```python
# UNSAFE: Pickle RCE
pickle.loads(user_data)
# SAFE: Use JSON or validate source
json.loads(user_data)

# UNSAFE: Format string injection
query = "SELECT * FROM users WHERE name = '%s'" % user_input
# SAFE: Parameterized
cursor.execute("SELECT * FROM users WHERE name = %s", (user_input,))
```
**Watch for:** `pickle`, `eval()`, `exec()`, `os.system()`, `subprocess` with `shell=True`

---

## Java
**Main Risks:** Deserialization RCE, XXE, JNDI injection
```java
// UNSAFE: Arbitrary deserialization
ObjectInputStream ois = new ObjectInputStream(userStream);
Object obj = ois.readObject();

// SAFE: Use allowlist or JSON
// Use Jackson with @JsonTypeInfo restrictions, or avoid deserialization entirely
```
**Watch for:** `ObjectInputStream`, `XMLDecoder`, JNDI lookups, Spring SpEL injection

---

## Go
**Main Risks:** SQL injection, path traversal, goroutine races
```go
// UNSAFE: String formatting in SQL
db.Query("SELECT * FROM users WHERE id = " + userID)
// SAFE: Parameterized
db.Query("SELECT * FROM users WHERE id = ?", userID)
```
**Watch for:** `fmt.Sprintf` in SQL, `filepath.Join` with user input, unsynchronized shared state

---

## PHP
**Main Risks:** SQLi, XSS, file inclusion, type juggling
```php
// UNSAFE: File inclusion
include($_GET['page'] . '.php');
// SAFE: Allowlist
$allowed = ['home', 'about'];
if (in_array($_GET['page'], $allowed)) include($_GET['page'] . '.php');

// UNSAFE: Loose comparison
if ($input == "0") { ... }  // "0e123" == "0" is true!
// SAFE: Strict comparison
if ($input === "0") { ... }
```
**Watch for:** `include`/`require` with user input, `eval`, `==` vs `===`, `$_REQUEST` usage

---

## C# / .NET
**Main Risks:** XXE, LINQ injection, deserialization
```csharp
// UNSAFE: XXE
XmlDocument doc = new XmlDocument();
doc.Load(userInput);

// SAFE: Disable external entities
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
XmlReader.Create(stream, settings);
```
**Watch for:** `BinaryFormatter`, `XmlSerializer`, LINQ with dynamic queries, ViewState deserialization

---

## Ruby
**Main Risks:** Mass assignment, YAML deserialization RCE
```ruby
# UNSAFE: Mass assignment
User.new(params[:user])
# SAFE: Strong parameters
User.new(params.require(:user).permit(:name, :email))

# UNSAFE: YAML RCE
YAML.load(user_input)
# SAFE: Use safe_load
YAML.safe_load(user_input)
```
**Watch for:** YAML.load, Marshal.load, eval, send with user input, .permit!

---

## Rust
**Main Risks:** Unsafe blocks, FFI boundary issues, integer overflow in release
```rust
// CAUTION: Unsafe bypasses safety
unsafe { ptr::read(user_ptr) }

// CAUTION: Release integer overflow
let x: u8 = 255;
let y = x + 1; // Wraps to 0 in release!
// SAFE: Use checked arithmetic
let y = x.checked_add(1).unwrap_or(255);
```
**Watch for:** `unsafe` blocks, FFI calls, integer overflow in release builds, `.unwrap()` on untrusted input

---

## Swift
**Main Risks:** Force unwrapping crashes, Objective-C interop
```swift
// UNSAFE: Force unwrap on untrusted data
let value = jsonDict["key"]!
// SAFE: Safe unwrapping
guard let value = jsonDict["key"] else { return }
```
**Watch for:** force unwrap (!), try!, ObjC bridging, NSSecureCoding misuse

---

## Kotlin
**Main Risks:** Null safety bypass, Java interop, serialization
```kotlin
// UNSAFE: Platform type from Java
val len = javaString.length // NPE if null
// SAFE: Explicit null check
val len = javaString?.length ?: 0
```
**Watch for:** Java interop nulls (! operator), reflection, serialization, platform types

---

## C / C++
**Main Risks:** Buffer overflow, use-after-free, format string
```c
// UNSAFE: Buffer overflow
char buf[10]; strcpy(buf, userInput);
// SAFE: Bounds checking
strncpy(buf, userInput, sizeof(buf) - 1);

// UNSAFE: Format string
printf(userInput);
// SAFE: Always use format specifier
printf("%s", userInput);
```
**Watch for:** `strcpy`, `sprintf`, `gets`, pointer arithmetic, manual memory management, integer overflow

---

## Scala
**Main Risks:** XXE, serialization, pattern matching exhaustiveness
```scala
// UNSAFE: XXE
val xml = XML.loadString(userInput)
// SAFE: Disable external entities
val factory = SAXParserFactory.newInstance()
factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
```
**Watch for:** Java interop issues, XML parsing, `Serializable`, exhaustive pattern matching

---

## R
**Main Risks:** Code injection, file path manipulation
```r
# UNSAFE: eval injection
eval(parse(text = user_input))

# UNSAFE: Path traversal
read.csv(paste0("data/", user_file))
# SAFE: Validate filename
if (grepl("^[a-zA-Z0-9]+\\.csv$", user_file)) read.csv(...)
```
**Watch for:** `eval()`, `parse()`, `source()`, `system()`, file path manipulation

---

## Perl
**Main Risks:** Regex injection, open() injection, taint mode bypass
```perl
# UNSAFE: Regex DoS
$input =~ /$user_pattern/;
# SAFE: Use quotemeta
$input =~ /\Q$user_pattern\E/;

# UNSAFE: open() command injection
open(FILE, $user_file);
# SAFE: Three-argument open
open(my $fh, '<', $user_file);
```
**Watch for:** Two-arg `open()`, regex from user input, backticks, `eval`, disabled taint mode

---

## Shell (Bash)
**Main Risks:** Command injection, word splitting, globbing
```bash
# UNSAFE: Unquoted variables
rm $user_file
# SAFE: Always quote
rm "$user_file"

# UNSAFE: eval
eval "$user_command"
# SAFE: Never eval user input
```
**Watch for:** Unquoted variables, `eval`, backticks, `$(...)` with user input, missing `set -euo pipefail`

---

## Lua
**Main Risks:** Sandbox escape, loadstring injection
```lua
-- UNSAFE: Code injection
loadstring(user_code)()
-- SAFE: Use sandboxed environment with restricted functions
```
**Watch for:** `loadstring`, `loadfile`, `dofile`, `os.execute`, `io` library, debug library

---

## Elixir
**Main Risks:** Atom exhaustion, code injection, ETS access
```elixir
# UNSAFE: Atom exhaustion DoS
String.to_atom(user_input)
# SAFE: Use existing atoms only
String.to_existing_atom(user_input)

# UNSAFE: Code injection
Code.eval_string(user_input)
# SAFE: Never eval user input
```
**Watch for:** `String.to_atom`, `Code.eval_string`, `:erlang.binary_to_term`, ETS public tables

---

## Dart / Flutter
**Main Risks:** Platform channel injection, insecure storage
```dart
// UNSAFE: Storing secrets in SharedPreferences
prefs.setString('auth_token', token);
// SAFE: Use flutter_secure_storage
secureStorage.write(key: 'auth_token', value: token);
```
**Watch for:** Platform channel data, `dart:mirrors`, `Function.apply`, insecure local storage

---

## PowerShell
**Main Risks:** Command injection, execution policy bypass
```powershell
# UNSAFE: Injection
Invoke-Expression $userInput
# SAFE: Avoid Invoke-Expression with user data

# UNSAFE: Unvalidated path
Get-Content $userPath
# SAFE: Validate path is within allowed directory
```
**Watch for:** `Invoke-Expression`, `& $userVar`, `Start-Process` with user args, `-ExecutionPolicy Bypass`

---

## SQL (All Dialects)
**Main Risks:** Injection, privilege escalation, data exfiltration
```sql
-- UNSAFE: String concatenation
"SELECT * FROM users WHERE id = " + userId

-- SAFE: Parameterized query (language-specific)
-- Use prepared statements in ALL cases
```
**Watch for:** Dynamic SQL, `EXECUTE IMMEDIATE`, stored procedures with dynamic queries, privilege grants

---

## Deep Security Analysis Mindset

When reviewing any language, think like a senior security researcher:

1. **Memory Model:** How does the language handle memory? Managed vs manual? GC pauses exploitable?
2. **Type System:** Weak typing = type confusion attacks. Look for coercion exploits.
3. **Serialization:** Every language has its pickle/Marshal equivalent. All are dangerous.
4. **Concurrency:** Race conditions, TOCTOU, atomicity failures specific to the threading model.
5. **FFI Boundaries:** Native interop is where type safety breaks down.
6. **Standard Library:** Historic CVEs in std libs (Python urllib, Java XML, Ruby OpenSSL).
7. **Package Ecosystem:** Typosquatting, dependency confusion, malicious packages.
8. **Build System:** Makefile/gradle/npm script injection during builds.
9. **Runtime Behavior:** Debug vs release differences (Rust overflow, C++ assertions).
10. **Error Handling:** How does the language fail? Silently? With stack traces? Fail-open?

**For any language not listed:** Research its specific CWE patterns, CVE history, and known footguns.

---

## When to Apply This Skill

- Reviewing or writing code in any specific programming language
- Auditing for language-specific footguns
- Cross-language security review (microservices, polyglot codebases)

Combine with **owasp-web-security** for web app review, **owasp-mobile-security** for mobile, or **owasp-llm-security** for LLM-powered apps.
