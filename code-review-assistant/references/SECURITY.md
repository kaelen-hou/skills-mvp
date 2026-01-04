# Security Review Checklist

## Injection Vulnerabilities

### SQL Injection
- [ ] Parameterized queries used instead of string concatenation
- [ ] ORM methods used correctly (no raw SQL with user input)
- [ ] Stored procedures validate input parameters

```python
# BAD
query = f"SELECT * FROM users WHERE id = {user_id}"

# GOOD
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

### XSS (Cross-Site Scripting)
- [ ] User input escaped before rendering in HTML
- [ ] Content-Security-Policy headers configured
- [ ] innerHTML/dangerouslySetInnerHTML avoided or sanitized

```javascript
// BAD
element.innerHTML = userInput;

// GOOD
element.textContent = userInput;
// or with sanitization
element.innerHTML = DOMPurify.sanitize(userInput);
```

### Command Injection
- [ ] No shell=True with user-controlled input
- [ ] subprocess uses list arguments, not strings
- [ ] os.system() avoided in favor of subprocess

```python
# BAD
os.system(f"ls {user_path}")

# GOOD
subprocess.run(["ls", user_path], shell=False)
```

### Path Traversal
- [ ] File paths validated against allowed directories
- [ ] No direct use of user input in file operations
- [ ] os.path.realpath() used to resolve symlinks

---

## Authentication & Authorization

### Authentication
- [ ] Passwords hashed with strong algorithm (bcrypt, argon2)
- [ ] Session tokens cryptographically random
- [ ] Multi-factor authentication for sensitive operations
- [ ] Password reset tokens expire appropriately

### Authorization
- [ ] Access control checks at every endpoint
- [ ] Role-based permissions verified server-side
- [ ] No reliance on client-side authorization
- [ ] Principle of least privilege applied

### Session Management
- [ ] Session tokens regenerated after login
- [ ] Sessions expire after inactivity
- [ ] Secure and HttpOnly flags on cookies
- [ ] CSRF protection implemented

---

## Data Protection

### Sensitive Data
- [ ] No secrets/credentials in code or config files
- [ ] Environment variables used for secrets
- [ ] Sensitive data encrypted at rest
- [ ] PII handled according to regulations

### Data Exposure
- [ ] API responses don't leak internal data
- [ ] Error messages don't expose system details
- [ ] Logs don't contain sensitive information
- [ ] Debug mode disabled in production

---

## Input Validation

### General Validation
- [ ] All user input validated server-side
- [ ] Input length limits enforced
- [ ] Type checking performed
- [ ] Whitelist validation preferred over blacklist

### File Uploads
- [ ] File type validated by content, not just extension
- [ ] File size limits enforced
- [ ] Uploads stored outside web root
- [ ] Filenames sanitized

---

## Cryptography

### Encryption
- [ ] Strong algorithms used (AES-256, RSA-2048+)
- [ ] No deprecated algorithms (MD5, SHA1, DES)
- [ ] Proper IV/nonce handling
- [ ] Keys stored securely, not in code

### Random Numbers
- [ ] Cryptographically secure random for security purposes
- [ ] secrets module in Python, crypto in Node.js
- [ ] No Math.random() for security tokens

---

## Logging & Error Handling

### Secure Logging
- [ ] No sensitive data in logs (passwords, tokens, PII)
- [ ] Log injection prevented
- [ ] Appropriate log levels used

### Error Handling
- [ ] Generic error messages to users
- [ ] Detailed errors only in logs
- [ ] No stack traces exposed to users
- [ ] Fail securely (deny by default)
