# 🤝 Contributing Guide

Thank you for considering a contribution! This is a personal cybersecurity learning
repository, but improvements, corrections, and additions from the community are very welcome.

---

## 📐 What You Can Contribute

| Type | Welcome? | How |
|---|:---:|---|
| Fix a factual error in notes | ✅ | Open a PR with the correction |
| Add a missing tool or technique | ✅ | Open a PR with your notes |
| Suggest a new topic or section | ✅ | Open an Issue with your idea |
| Add a useful resource or link | ✅ | Edit `RESOURCES.md` and PR |
| Report a security concern | ✅ | See `SECURITY.md` — use private channel |
| Spam, self-promotion, or unrelated content | ❌ | Will be closed without review |

---

## 🚀 How to Contribute (Step by Step)

### 1. Fork the Repository

Click **Fork** at the top right of this page, then clone your fork:

```bash
git clone https://github.com/YOUR_USERNAME/cybersec-notes.git
cd cybersec-notes
```

### 2. Create a Branch

Use a descriptive branch name:

```bash
# For a fix
git checkout -b fix/sql-injection-typo

# For new content
git checkout -b add/nmap-advanced-cheatsheet

# For a resource addition
git checkout -b resources/add-portswigger-labs
```

### 3. Make Your Changes

Follow the content standards below. Then stage and commit:

```bash
git add .
git commit -m "add: nmap advanced scanning cheatsheet"
```

**Commit message format:**

```
<type>: <short description>

Types: add | fix | update | remove | refactor
```

### 4. Push and Open a Pull Request

```bash
git push origin your-branch-name
```

Then open a **Pull Request** on GitHub. Use the PR template — it will load automatically.

---

## ✍️ Content Standards

### Writing Style

- Use **clear, plain English** — as if explaining to a fellow learner
- Keep sentences short and scannable
- Use code blocks for all commands, payloads, and output:

  ````markdown
  ```bash
  nmap -sV -sC -oN scan.txt 10.10.10.10
  ```
  ````

- Use tables for comparisons and reference data
- Include a brief explanation alongside every tool or command — not just the command itself

### File Naming

```
kebab-case.md           ✅  sql-injection.md
snake_case.md           ❌  sql_injection.md
Title Case.md           ❌  SQL Injection.md
```

### Markdown Structure

Each notes file should follow this template:

```markdown
# Topic Name

> One-line description of what this covers.

---

## Overview
Brief explanation of the concept.

## How It Works
Technical detail.

## Commands / Payloads
Code blocks with explanations.

## Defense / Mitigation
How to protect against this (always include this section).

## References
- [Link text](url)
```

---

## ⚖️ Ethical Standards

All contributions **must** comply with [`ETHICAL_USE.txt`](./ETHICAL_USE.txt).

Contributions will be **rejected** if they:

- Contain working exploits targeting real production systems
- Include malware, ransomware, or RAT source code
- Provide step-by-step instructions for illegal activity
- Contain real credentials, IPs, or sensitive data
- Violate the Code of Conduct

When in doubt, ask in an Issue before opening a PR.

---

## 🔍 Pull Request Review Checklist

Before submitting your PR, confirm:

- [ ] Content is accurate and relevant to cybersecurity learning
- [ ] No real credentials, tokens, or sensitive data included
- [ ] Commands and payloads are explained, not just listed
- [ ] Markdown renders correctly (check the preview tab)
- [ ] Branch is up to date with `main`
- [ ] Commit messages follow the format above

---

## 💬 Questions?

Open an Issue with the label `question` and I'll respond as soon as I can.

---

*Thanks for helping make this a better learning resource for everyone!*  
— [@nikhiltomar2712](https://github.com/nikhiltomar2712)
