# OWASP Security Skills for Claude Code

A complete suite of Claude Code skills providing the latest OWASP security best practices (2025-2026) for developers building secure web applications, LLM-powered systems, AI/data-centric applications, and mobile apps.

**Available in two flavors:**
- **Focused skills** (recommended) — five specialized skills loaded only when relevant. Lower token cost per invocation.
- **Unified skill** — one comprehensive file covering everything. Simpler to install, higher token cost.

---

## Quick Install

### Recommended: Focused Skills (Lower Token Usage)

Install all five focused skills with one command:

```bash
for skill in owasp-web-security owasp-llm-security owasp-ai-exchange owasp-mobile-security owasp-language-quirks; do
  curl -sL "https://raw.githubusercontent.com/alraisi/claude-code-owasp/main/.claude/skills/$skill/SKILL.md" \
    -o ".claude/skills/$skill/SKILL.md" --create-dirs
done
```

Or globally for all projects:

```bash
for skill in owasp-web-security owasp-llm-security owasp-ai-exchange owasp-mobile-security owasp-language-quirks; do
  curl -sL "https://raw.githubusercontent.com/alraisi/claude-code-owasp/main/.claude/skills/$skill/SKILL.md" \
    -o "$HOME/.claude/skills/$skill/SKILL.md" --create-dirs
done
```

### Alternative: Unified Single-File Skill

If you prefer a single file with everything:

```bash
curl -sL https://raw.githubusercontent.com/alraisi/claude-code-owasp/main/.claude/skills/owasp-security-unified/SKILL.md \
  -o .claude/skills/owasp-security/SKILL.md --create-dirs
```

Or globally:

```bash
curl -sL https://raw.githubusercontent.com/alraisi/claude-code-owasp/main/.claude/skills/owasp-security-unified/SKILL.md \
  -o ~/.claude/skills/owasp-security/SKILL.md --create-dirs
```

---

## The Five Focused Skills

| Skill | Lines | Activates When You... | Covers |
|-------|-------|----------------------|--------|
| **owasp-web-security** | ~217 | Build web apps, design APIs, write auth code, review backend code | OWASP Top 10:2025, ASVS 5.0, Agentic AI 2026, secure code patterns |
| **owasp-llm-security** | ~289 | Build LLM-powered apps, RAG pipelines, AI assistants | OWASP Top 10 for LLM Applications 2025 (LLM01–LLM10) |
| **owasp-ai-exchange** | ~391 | Design AI governance, threat-model AI systems, do AI red-teaming | OWASP AI Exchange: G.U.A.R.D., 40+ controls, 7-layer prompt injection defense, AI privacy |
| **owasp-mobile-security** | ~630 | Build, review, or test Android/iOS apps | OWASP MASVS v2.1.0 + MASTG v1.7.0 (all 8 control groups) |
| **owasp-language-quirks** | ~332 | Review code in any specific programming language | 20+ languages with security footguns and safe patterns |

### Why focused skills?

The unified skill is 1,596 lines (~10K tokens). When you invoke it for a Django review, you're paying tokens for MASVS Frida scripts, Kotlin Keystore patterns, and AI Exchange G.U.A.R.D. that you'll never use. Focused skills load only what's relevant:

- **Django web review** → ~217 lines loaded (~75% reduction)
- **Mobile pentest** → ~630 lines loaded (~62% reduction)
- **AI agent review** → ~680 lines loaded (`owasp-llm-security` + `owasp-ai-exchange`, ~57% reduction)

Skills cross-reference each other, so when you're working on something that spans domains (e.g., an LLM-powered mobile app), Claude can pull just the relevant pair.

---

## The Unified Skill

`owasp-security-unified` (1,596 lines) is the original all-in-one skill containing everything from the five focused skills in a single file. Use it if:

- You want simpler installation (one file, one path)
- You frequently work across all domains and don't mind the token cost
- You prefer browsing all controls in a single document
- You're integrating into tooling that expects a single skill

The content is identical — just packaged differently.

---

## Coverage Matrix

### Standards Covered

| Standard | Version | Focused Skill | Also In Unified |
|----------|---------|---------------|-----------------|
| OWASP Top 10 | 2025 | owasp-web-security | ✅ |
| OWASP ASVS | 5.0.0 | owasp-web-security | ✅ |
| OWASP Top 10 for Agentic Applications | 2026 | owasp-web-security | ✅ |
| OWASP Top 10 for LLM Applications | 2025 | owasp-llm-security | ✅ |
| OWASP AI Exchange | Latest | owasp-ai-exchange | ✅ |
| OWASP MASVS | v2.1.0 | owasp-mobile-security | ✅ |
| OWASP MASTG | v1.7.0 | owasp-mobile-security | ✅ |
| Language-specific patterns | — | owasp-language-quirks | ✅ |

### AI/LLM Security Coverage

| Layer | Skill | What It Covers |
|-------|-------|----------------|
| LLM application vulnerabilities | owasp-llm-security | Prompt injection, data disclosure, supply chain, excessive agency, output handling, RAG weaknesses, misinformation, unbounded consumption |
| All AI system types | owasp-ai-exchange | Governance (G.U.A.R.D.), input/dev-time/runtime threats, 40+ named controls, AI privacy, red-teaming framework, regulatory compliance |
| AI agent systems | owasp-web-security | Goal hijacking, tool misuse, privilege abuse, cascading failures, rogue agents (ASI01–ASI10) |

### Mobile Security Coverage (owasp-mobile-security)

| Group | What It Covers |
|-------|----------------|
| MASVS-STORAGE | Secure data at rest, backup exclusion, log leakage |
| MASVS-CRYPTO | Forbidden algorithms, Android Keystore, iOS Secure Enclave |
| MASVS-AUTH | OAuth/OIDC, JWT, biometric (CryptoObject) |
| MASVS-NETWORK | TLS enforcement, certificate pinning (OkHttp + URLSession) |
| MASVS-PLATFORM | IPC security, WebView hardening, FLAG_SECURE |
| MASVS-CODE | Binary protections (PIE, canaries), R8/ProGuard, dependency scanning |
| MASVS-RESILIENCE | Root/jailbreak detection, anti-tampering, obfuscation |
| MASVS-PRIVACY | Permission minimization, app store labels, data deletion |
| MASTG Methodology | APK extraction, jadx/apktool, Frida/Objection scripts |

### Languages Covered (owasp-language-quirks)

| Web | Systems | Scripting | Data | Mobile |
|-----|---------|-----------|------|--------|
| JavaScript/TypeScript | C/C++ | Python | SQL | Android (Kotlin) |
| PHP | Rust | Ruby | Shell/Bash | iOS (Swift) |
| Java | Go | Perl | | Dart/Flutter |
| C# | | Lua | | |
| Scala | | PowerShell | | |
| | | Elixir | | |
| | | R | | |

---

## Usage Examples

Once installed, Claude Code automatically activates the right skill based on your task:

```
"Review this code for security issues"                  → owasp-web-security + owasp-language-quirks
"Is this authentication implementation secure?"         → owasp-web-security
"Review this RAG pipeline for LLM security issues"      → owasp-llm-security
"Check this AI agent for OWASP agentic risks"           → owasp-web-security + owasp-llm-security
"Help me threat model my AI system"                     → owasp-ai-exchange
"Red-team this LLM using OWASP AI Exchange framework"   → owasp-ai-exchange + owasp-llm-security
"Audit this Android app for security issues"            → owasp-mobile-security + owasp-language-quirks
"Review this Python code for security footguns"         → owasp-language-quirks
```

If you've installed the unified skill instead, all of the above route to `owasp-security-unified`.

---

## Alternative Installation

### Clone Full Repository

```bash
git clone https://github.com/alraisi/claude-code-owasp.git
# Use focused skills:
cp -r claude-code-owasp/.claude/skills/owasp-* YOUR_PROJECT/.claude/skills/
# Or use unified:
cp -r claude-code-owasp/.claude/skills/owasp-security-unified YOUR_PROJECT/.claude/skills/owasp-security
```

### Install Specific Focused Skill

If you only need one skill (e.g., just mobile security):

```bash
curl -sL https://raw.githubusercontent.com/alraisi/claude-code-owasp/main/.claude/skills/owasp-mobile-security/SKILL.md \
  -o .claude/skills/owasp-mobile-security/SKILL.md --create-dirs
```

---

## Repository Structure

```
.claude/skills/
├── owasp-web-security/          # Web apps, ASVS, Agentic AI
│   └── SKILL.md
├── owasp-llm-security/          # OWASP LLM Top 10 2025
│   └── SKILL.md
├── owasp-ai-exchange/           # AI Exchange comprehensive framework
│   └── SKILL.md
├── owasp-mobile-security/       # MASVS + MASTG (Android/iOS)
│   └── SKILL.md
├── owasp-language-quirks/       # 20+ languages
│   └── SKILL.md
└── owasp-security-unified/      # All-in-one alternative
    └── SKILL.md
```

---

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

When updating content, please update both the relevant focused skill **and** the unified skill to keep them aligned.

---

## Sources

- [OWASP Top 10:2025](https://owasp.org/Top10/)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/)
- [OWASP AI Exchange](https://owaspai.org/)
- [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/)
- [OWASP MASVS v2.1.0](https://mas.owasp.org/MASVS/)
- [OWASP MASTG v1.7.0](https://mas.owasp.org/MASTG/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

---

## License

MIT License - See LICENSE file for details.

---

**Keywords:** OWASP, security, Claude Code, AI security, LLM security, mobile security, application security, ASVS, MASVS, MASTG, Android security, iOS security, secure coding, vulnerability, injection, XSS, CSRF, authentication, authorization, prompt injection, RAG security, AI Exchange, agentic AI, LLM Top 10, certificate pinning, reverse engineering, focused skills, token optimization
