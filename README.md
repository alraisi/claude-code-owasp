# OWASP Security Skill for Claude Code

A Claude Code skill providing the latest OWASP security best practices (2025-2026) for developers building secure web applications, LLM-powered systems, AI/data-centric applications, and mobile apps.

## Quick Install (One Line)

Add this skill to any project with a single command:

```bash
curl -sL https://raw.githubusercontent.com/alraisi/claude-code-owasp/main/.claude/skills/owasp-security/SKILL.md -o .claude/skills/owasp-security/SKILL.md --create-dirs
```

Or install globally for all projects:

```bash
curl -sL https://raw.githubusercontent.com/alraisi/claude-code-owasp/main/.claude/skills/owasp-security/SKILL.md -o ~/.claude/skills/owasp-security/SKILL.md --create-dirs
```

## What's Included

### Claude Code Skill
Location: `.claude/skills/owasp-security/SKILL.md`

- **OWASP Top 10:2025** quick reference table for web applications
- **OWASP Top 10 for LLM Applications 2025** — LLM01–LLM10 with root causes, code patterns (prompt injection labeling, output sanitization, RAG access control, rate limiting), and a full review checklist
- **OWASP AI Exchange** — the global consensus framework for all AI systems:
  - G.U.A.R.D. governance model (Govern, Understand, Adapt, Reduce, Demonstrate)
  - Threat taxonomy: Input threats, Development-time threats, Runtime threats
  - Control reference (`#HASHTAG` controls aligned with ISO/IEC 27090/27091 and EU AI Act)
  - Seven layers of prompt injection protection
  - Implementation details for key controls (I/O handling, sensitive output filtering, model watermarking)
  - AI security testing framework and red-teaming tools table
  - AI privacy principles and legislation tracker
  - AI Exchange review checklist
- **OWASP Agentic AI Security (2026)** — ASI01–ASI10 risks for AI agent systems
- **ASVS 5.0** key requirements by verification level (L1/L2/L3)
- **Security code review checklists** for input handling, auth, access control, data protection, and error handling
- **Secure code patterns** with unsafe/safe examples
- **OWASP MAS: MASVS v2.1.0 + MASTG v1.7.0** — complete mobile application security standard:
  - All 8 control groups: STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE, PRIVACY
  - Android (Kotlin) and iOS (Swift) secure code patterns for every group
  - Forbidden crypto algorithm table, Android Keystore / iOS Secure Enclave patterns
  - Certificate pinning (OkHttp + iOS URLSession), TLS enforcement
  - WebView hardening, IPC security, FLAG_SECURE UI protection
  - MASTG testing methodology: APK extraction, jadx/apktool, Frida/Objection scripts
  - Binary protection checks (PIE, stack canaries, R8/ProGuard)
  - Root/jailbreak detection, anti-tampering, obfuscation techniques
  - Full mobile security review checklist
- **Language-specific security quirks** for 20+ languages with deep analysis guidance

### Research Report
Location: `OWASP-2025-2026-Report.md`

Comprehensive documentation covering all OWASP 2025-2026 standards.

## Usage

Once installed, Claude Code automatically activates this skill when you:
- Review code for security vulnerabilities
- Implement authentication or authorization
- Handle user input or external data
- Work with cryptography or password storage
- Design API endpoints
- **Build, review, or test any mobile application (Android/iOS/cross-platform)**
- **Build or review any LLM-powered application**
- **Work with AI agents, RAG pipelines, or model integrations**
- **Evaluate third-party models or ML dependencies**
- **Design or audit any AI system**
- **Perform AI security testing or red-teaming**

### Example Prompts
```
"Review this code for security issues"
"Is this authentication implementation secure?"
"What are the security risks in this Python code?"
"Help me implement secure session management"
"Check this AI agent for OWASP agentic risks"
"Review this RAG pipeline for LLM security issues"
"What controls should I apply to my LLM application?"
"Help me red-team this AI system using the OWASP AI Exchange framework"
```

## Covered Standards

| Standard | Version | Focus |
|----------|---------|-------|
| OWASP Top 10 | 2025 | Web application vulnerabilities |
| OWASP Top 10 for LLM Applications | 2025 | LLM-specific vulnerabilities (prompt injection, sensitive disclosure, supply chain, excessive agency, etc.) |
| OWASP AI Exchange | Latest | Comprehensive AI threat & control framework for all AI types; feeds ISO/IEC 27090/27091 and EU AI Act |
| OWASP ASVS | 5.0.0 | Security verification requirements |
| OWASP Agentic AI | 2026 | AI agent security risks (ASI01–ASI10) |
| OWASP MASVS | 2.1.0 | Mobile application security verification standard (Android & iOS) |
| OWASP MASTG | 1.7.0 | Mobile application security testing guide |

## AI Security Coverage

The skill now provides end-to-end coverage for AI/LLM systems:

| Layer | Standard | What It Covers |
|-------|----------|----------------|
| LLM application vulnerabilities | OWASP LLM Top 10:2025 | Prompt injection, data disclosure, supply chain, excessive agency, output handling, RAG weaknesses, misinformation, unbounded consumption |
| All AI system types | OWASP AI Exchange | Governance, input threats, development-time threats, runtime threats, privacy, red-teaming, regulatory compliance |
| AI agent systems | OWASP Agentic AI 2026 | Goal hijacking, tool misuse, privilege abuse, cascading failures, rogue agents |
| Mobile applications (Android & iOS) | OWASP MASVS v2.1.0 + MASTG v1.7.0 | Storage, crypto, auth, network, platform interaction, code quality, resilience, privacy |

## Language Coverage

Security quirks including:

| Web | Systems | Scripting | Data | Mobile |
|-----|---------|-----------|------|--------|
| JavaScript/TypeScript | C/C++ | Python | SQL | Android (Kotlin) |
| PHP | Rust | Ruby | Shell | iOS (Swift) |
| Java | Go | | |
| C# | | | |

## Alternative Installation

### Clone Full Repository
```bash
git clone https://github.com/alraisi/claude-code-owasp.git
cp -r claude-code-owasp/.claude/skills/owasp-security YOUR_PROJECT/.claude/skills/
```

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Sources

- [OWASP Top 10:2025](https://owasp.org/Top10/)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/)
- [OWASP AI Exchange](https://owaspai.org/)
- [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP MASVS v2.1.0](https://mas.owasp.org/MASVS/)
- [OWASP MASTG v1.7.0](https://mas.owasp.org/MASTG/)

## License

MIT License - See LICENSE file for details.

---

**Keywords:** OWASP, security, Claude Code, AI security, LLM security, mobile security, application security, ASVS, MASVS, MASTG, Android security, iOS security, secure coding, vulnerability, injection, XSS, CSRF, authentication, authorization, prompt injection, RAG security, AI Exchange, agentic AI, LLM Top 10, certificate pinning, reverse engineering
