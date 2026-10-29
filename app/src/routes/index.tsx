import { createFileRoute } from "@tanstack/react-router";
import { scanSpamLinks } from "../lib/spam-link-scanner";
import { strFromU8, unzipSync } from "fflate";
import { useMemo, useRef, useState } from "react";
import {
  Activity, AlertOctagon, AlertTriangle, ArrowDownToLine, ArrowRight, ArrowUpRight,
  BadgeCheck, Check, ChevronDown, ChevronRight, CircleHelp, Clipboard, Code2,
  FileCode2, FileUp, Fingerprint, LockKeyhole, Menu, Play, Radar,
  ScanSearch, Shield, ShieldAlert, ShieldCheck, Sparkles, Terminal, Upload,
  X, Zap, Link2, Globe, ListChecks, ExternalLink, SearchCheck,
} from "lucide-react";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "CodeCook | Code smarter. Ship safer." },
      { name: "description", content: "A privacy-first source code security scanner for developers. Find risky patterns, understand the impact, and apply safer fixes." },
    ],
  }),
  component: CodeCookApp,
});

type Severity = "Critical" | "High" | "Medium" | "Low";
type Finding = {
  id: string; rule: string; title: string; severity: Severity; file: string; line: number;
  snippet: string; description: string; fix: string; cwe: string; confidence: "High" | "Medium" | "Low";
};
type SourceFile = { name: string; content: string };
type UploadIssue = { id: string; file: string; reason: string; line?: number };

const SAMPLE = `import os\nimport sqlite3\n\nAPI_KEY = "sk_live_1234567890abcdef"\n\ndef get_user(user_id):\n    query = "SELECT * FROM users WHERE id = " + user_id\n    db = sqlite3.connect("app.db")\n    return db.execute(query).fetchall()\n\ndef run_command(user_input):\n    os.system("echo " + user_input)\n\n# Debug endpoint left enabled\nDEBUG = True\n`;

const RULES: Array<{
  id: string; title: string; severity: Severity; regex: RegExp; description: string; fix: string; cwe: string; confidence?: "High" | "Medium" | "Low";
}> = [
  // Secrets and sensitive data
  { id: "SEC-001", title: "Hardcoded credential or API key", severity: "Critical", regex: /(?:api[_-]?key|secret|password|passwd|token|client[_-]?secret)\s*[:=]\s*["'][^"'\n]{8,}["']/i, description: "A credential-like value appears to be embedded in source code. If committed or shared, it may grant unintended access.", fix: "Rotate the exposed credential, move it to an environment variable or secret manager, and add local secret files to .gitignore.", cwe: "CWE-798" },
  { id: "SEC-002", title: "Private key material in source", severity: "Critical", regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, description: "A private-key header appears in the source. Anyone with the complete key may impersonate its owner.", fix: "Revoke or rotate the key, remove it from repository history, and store keys in a managed secret store.", cwe: "CWE-321" },
  { id: "SEC-003", title: "Possible cloud access key", severity: "Critical", regex: /\b(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b/, description: "The string resembles an AWS access key identifier. Confirm it is not a real credential.", fix: "Disable and rotate the key, audit recent usage, and use short-lived role-based credentials.", cwe: "CWE-798" },
  { id: "SEC-004", title: "Possible high-entropy secret", severity: "High", regex: /(?:secret|token|api[_-]?key|credential)\s*[:=]\s*["'][A-Za-z0-9_.\/+=-]{24,}["']/i, description: "A long token-like value is assigned to a security-sensitive variable.", fix: "Verify whether this is a real secret. If so, rotate it and load it from a secret manager.", cwe: "CWE-798", confidence: "Medium" },
  { id: "SEC-005", title: "Sensitive data written to logs", severity: "High", regex: /(?:console\.log|logger\.(?:info|debug|warn)|print)\s*\([^\n]*(?:password|passwd|access[_-]?token|refresh[_-]?token|authorization|credit.?card|ssn)/i, description: "A logging call may expose credentials or personal information in logs.", fix: "Remove sensitive fields from logs. Redact secrets and use structured logging with an explicit safe-field allowlist.", cwe: "CWE-532" },
  // Injection families
  { id: "INJ-001", title: "Possible SQL injection", severity: "High", regex: /(?:SELECT|UPDATE|DELETE|INSERT|WHERE|ORDER BY)[^\n]*(?:\+\s*\w+|\$\{[^}]+\}|%\s*\w+|\.format\s*\(|f["'])/i, description: "SQL appears to be assembled with concatenation or interpolation. Untrusted input could change the query structure.", fix: "Use parameterized queries or prepared statements. Keep query structure separate from user-controlled values.", cwe: "CWE-89" },
  { id: "INJ-002", title: "Dynamic NoSQL query construction", severity: "High", regex: /(?:find|findOne|updateOne|deleteOne|aggregate)\s*\(\s*\{[^\n]*(?:req\.(?:body|query|params)|request\.(?:body|query|params))/i, description: "Request-controlled data may be inserted directly into a NoSQL query object.", fix: "Validate and allowlist fields and operators; build query objects from trusted schema fields instead of passing request objects through.", cwe: "CWE-943", confidence: "Medium" },
  { id: "INJ-003", title: "Shell command built from input", severity: "High", regex: /(?:os\.system\s*\(|shell\s*=\s*True|child_process\.(?:exec|execSync)\s*\(|Runtime\.getRuntime\(\)\.exec\s*\()[^\n]*(?:\+|\$\{|\bf["'])/i, description: "A shell command may include dynamic data. Crafted input can sometimes execute unintended commands.", fix: "Avoid shell invocation where possible. Use process APIs with separate arguments and validate each argument against an allowlist.", cwe: "CWE-78" },
  { id: "INJ-004", title: "Dynamic code evaluation", severity: "High", regex: /\beval\s*\(|new\s+Function\s*\(/, description: "Dynamic evaluation turns strings into executable code and can create an injection path when data is untrusted.", fix: "Remove eval/new Function. Use explicit parsing, safe expressions, or a fixed lookup table.", cwe: "CWE-95" },
  { id: "INJ-005", title: "Potential unsafe HTML insertion", severity: "High", regex: /(?:innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML\s*=)/, description: "Raw HTML insertion can execute attacker-controlled markup if the value is not safely sanitized.", fix: "Prefer textContent or framework text rendering. Sanitize required HTML with a maintained allowlist sanitizer.", cwe: "CWE-79" },
  { id: "INJ-006", title: "Server-side template injection risk", severity: "High", regex: /(?:render_template_string|Template)\s*\([^\n]*(?:request\.|req\.|user_input|params\[)/i, description: "User-controlled input may be passed into a template string that gets interpreted by a template engine.", fix: "Use fixed template files and pass user input as escaped data, never as template source.", cwe: "CWE-1336", confidence: "Medium" },
  { id: "INJ-007", title: "LDAP filter built from input", severity: "High", regex: /(?:search_filter|ldap_filter|filter)\s*=\s*["'][^\n]*(?:\+|%s|\.format\s*\()[^\n]*(?:user|input|request)/i, description: "LDAP filter text may be assembled using user-controlled data.", fix: "Escape LDAP filter values with a library designed for LDAP and use safe query-building APIs.", cwe: "CWE-90", confidence: "Medium" },
  { id: "INJ-008", title: "XPath expression built dynamically", severity: "High", regex: /(?:xpath|evaluate)\s*\([^\n]*(?:\+|\.format\s*\(|\$\{)/i, description: "A dynamic XPath expression may allow input to change the query meaning.", fix: "Use XPath variables or safely escape input using the XML library's supported APIs.", cwe: "CWE-643", confidence: "Medium" },
  { id: "INJ-009", title: "Potential expression-language injection", severity: "High", regex: /(?:SpEL|OGNL|ExpressionParser|createExpression)\s*[^\n]*(?:request|input|param)/i, description: "Expression-language APIs may evaluate expressions influenced by request data.", fix: "Do not evaluate user-supplied expressions. Restrict expression features and use trusted predefined expressions.", cwe: "CWE-917", confidence: "Medium" },
  { id: "INJ-010", title: "Regex built from untrusted input", severity: "Medium", regex: /new\s+RegExp\s*\([^\n]*(?:req\.|request\.|userInput|user_input|params)/i, description: "Untrusted input is used to construct a regular expression, which may alter matching behavior or cause excessive processing.", fix: "Escape literal input, impose length limits, and avoid running attacker-controlled patterns on large strings.", cwe: "CWE-1333", confidence: "Medium" },
  { id: "INJ-011", title: "Potential ReDoS-prone nested quantifier", severity: "Medium", regex: /new\s+RegExp\s*\(["'][^"']*(?:\([^)]*[+*][^)]*\)[+*]|\([^)]*\|[^)]*\)[+*])/, description: "A regex literal appears to contain a nested or repeated ambiguous pattern that can be expensive on crafted input.", fix: "Review worst-case complexity, simplify nested quantifiers, and enforce input length limits.", cwe: "CWE-1333", confidence: "Medium" },
  // File and network handling
  { id: "PATH-001", title: "Potential path traversal", severity: "High", regex: /(?:readFile|readFileSync|open|sendFile|FileInputStream)\s*\([^\n]*(?:req\.|request\.|user_input|filename|fileName|\.\.\/)/i, description: "A file operation may use request-controlled path data, potentially allowing access outside an intended directory.", fix: "Resolve paths against a fixed base directory, canonicalize them, and verify the final path remains inside that directory.", cwe: "CWE-22", confidence: "Medium" },
  { id: "PATH-002", title: "Unsafe archive extraction path", severity: "High", regex: /(?:extractall|extractTo|unzip|tar\.extract)\s*\([^\n]*(?:upload|archive|file|request)/i, description: "Archive extraction may process attacker-controlled paths or archive entries.", fix: "Reject absolute paths and traversal segments, verify each destination remains under the extraction directory, and limit expanded size.", cwe: "CWE-22", confidence: "Medium" },
  { id: "NET-001", title: "Potential server-side request forgery", severity: "High", regex: /(?:fetch|axios\.(?:get|post)|requests\.get|urlopen|http\.Get)\s*\([^\n]*(?:req\.|request\.|user_url|target_url|callback_url)/i, description: "A server-side HTTP client may request a URL influenced by user input, which can expose internal services.", fix: "Allowlist trusted destinations, block private/link-local IP ranges after DNS resolution, and restrict redirects and protocols.", cwe: "CWE-918", confidence: "Medium" },
  { id: "NET-002", title: "TLS certificate verification disabled", severity: "High", regex: /(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CERT_NONE|InsecureSkipVerify\s*:\s*true)/i, description: "Disabling certificate verification can make encrypted connections vulnerable to interception.", fix: "Enable certificate validation and configure the correct CA chain. Do not suppress TLS checks in production.", cwe: "CWE-295" },
  { id: "NET-003", title: "Unencrypted HTTP endpoint", severity: "Low", regex: /http:\/\/(?!localhost|127\.0\.0\.1)[\w.-]+\.[a-z]{2,}(?:\/[^\s"']*)?/i, description: "A plain HTTP URL may transmit data without transport encryption.", fix: "Use HTTPS for network endpoints and verify redirects and certificate validation.", cwe: "CWE-319", confidence: "Medium" },
  { id: "NET-004", title: "Potential open redirect", severity: "High", regex: /(?:res\.redirect|redirect|sendRedirect)\s*\([^\n]*(?:req\.|request\.|next|returnUrl|redirect_uri|redirectTo)/i, description: "A redirect destination may be controlled by a request parameter, enabling trusted-site phishing flows.", fix: "Accept only relative paths or validate destinations against a strict allowlist of trusted hosts.", cwe: "CWE-601", confidence: "Medium" },
  { id: "NET-005", title: "HTTP client follows redirects without destination checks", severity: "Medium", regex: /(?:allow_redirects\s*=\s*True|followRedirects\s*:\s*true)/i, description: "Automatic redirects can complicate SSRF defenses when the original URL is user-controlled.", fix: "When fetching user-supplied URLs, validate each redirect target and enforce a redirect limit.", cwe: "CWE-918", confidence: "Medium" },
  // Deserialization and parsers
  { id: "SER-001", title: "Unsafe Python pickle deserialization", severity: "High", regex: /\bpickle\.(?:loads?|Unpickler)\s*\(/, description: "Loading untrusted pickle data can execute arbitrary code during deserialization.", fix: "Never unpickle untrusted data. Prefer JSON with schema validation or a non-executable data format.", cwe: "CWE-502" },
  { id: "SER-002", title: "Unsafe YAML loader", severity: "High", regex: /yaml\.(?:load|unsafe_load)\s*\(/i, description: "A YAML loader may construct arbitrary Python objects when processing untrusted documents.", fix: "Use yaml.safe_load or a safe loader and validate the parsed structure against a schema.", cwe: "CWE-502", confidence: "Medium" },
  { id: "SER-003", title: "Potential unsafe Java deserialization", severity: "High", regex: /ObjectInputStream\s*\(|readObject\s*\(/, description: "Java native object deserialization can be dangerous when the input stream is untrusted.", fix: "Avoid native deserialization for untrusted input. Use a safer format and strict type allowlists where unavoidable.", cwe: "CWE-502", confidence: "Medium" },
  { id: "SER-004", title: "XML external entity risk", severity: "High", regex: /(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\s*\.?(?:newInstance|newFactory)\s*\(/, description: "XML parser construction should be checked for external entity and DTD restrictions.", fix: "Disable DOCTYPE declarations and external general/parameter entities, and enable secure processing for the chosen parser.", cwe: "CWE-611", confidence: "Medium" },
  { id: "SER-005", title: "Unsafe object construction from input", severity: "High", regex: /(?:ObjectInputStream|unserialize|unserialize\s*\(|Marshal\.load)\s*\(/, description: "Native object deserialization can invoke constructors or restore unexpected object state.", fix: "Avoid deserializing untrusted native objects; validate data using a non-executable format.", cwe: "CWE-502", confidence: "Medium" },
  // Authentication, authorization and sessions
  { id: "AUTH-001", title: "Weak password hashing algorithm", severity: "High", regex: /(?:md5|sha1)\s*\([^\n]*(?:password|passwd|credential)/i, description: "MD5 and SHA-1 are not suitable for password storage because they are fast to brute-force.", fix: "Use Argon2id, scrypt, or bcrypt with an appropriate work factor and unique salts.", cwe: "CWE-916", confidence: "Medium" },
  { id: "AUTH-002", title: "Password compared in plain text", severity: "High", regex: /(?:password|passwd)\s*={2,3}\s*(?:req\.|request\.|input|userInput|body\.)/i, description: "A password comparison appears to use raw input directly instead of a password-hashing verifier.", fix: "Store only salted password hashes and verify using the password-hashing library's verify function.", cwe: "CWE-256", confidence: "Medium" },
  { id: "AUTH-003", title: "JWT signature verification disabled", severity: "Critical", regex: /(?:verify\s*:\s*false|ignoreExpiration\s*:\s*true|algorithms\s*:\s*\[[^\]]*["']none["'])/i, description: "Token verification may be disabled or weakened, potentially allowing forged or expired tokens.", fix: "Require signature verification with an explicit algorithm allowlist and validate issuer, audience, and expiration.", cwe: "CWE-347", confidence: "Medium" },
  { id: "AUTH-004", title: "JWT uses a hardcoded signing secret", severity: "Critical", regex: /(?:jwt|token).{0,40}(?:secret|key)\s*[:=]\s*["'][^"']{6,}["']/i, description: "A token signing secret may be embedded in source code and recoverable by repository readers.", fix: "Rotate the signing secret and load it from a secret manager. Use strong random key material.", cwe: "CWE-321", confidence: "Medium" },
  { id: "AUTH-005", title: "Permissive authorization check", severity: "High", regex: /(?:isAdmin|is_admin|admin)\s*={2,3}\s*(?:true|1|["']true["'])[^\n]*(?:\|\||or\b)/i, description: "An authorization condition combines an admin check with a permissive OR condition.", fix: "Use explicit deny-by-default authorization logic and test both allowed and denied roles.", cwe: "CWE-862", confidence: "Medium" },
  { id: "AUTH-006", title: "Potential mass assignment", severity: "High", regex: /(?:Object\.assign\s*\(\s*(?:user|account|profile)|\.update\s*\(\s*(?:req\.body|request\.body)|\*\*request\.data)/i, description: "Request data may be copied directly into a model or update operation, allowing protected fields to be changed.", fix: "Build an explicit allowlisted DTO from permitted fields; never bind arbitrary request properties to sensitive models.", cwe: "CWE-915", confidence: "Medium" },
  { id: "AUTH-007", title: "Insecure direct object reference review", severity: "Medium", regex: /(?:findById|findOne|SELECT\s+\*\s+FROM)[^\n]*(?:req\.params|request\.args|user_id|accountId)/i, description: "A record lookup uses an externally supplied identifier. Verify ownership or tenant authorization before returning or modifying the record.", fix: "Scope every object query to the authenticated principal or tenant and add cross-user authorization tests.", cwe: "CWE-639", confidence: "Medium" },
  { id: "AUTH-008", title: "Session cookie missing secure options", severity: "Medium", regex: /(?:cookie|session)\s*\([^\n]*(?:httpOnly\s*:\s*false|secure\s*:\s*false|sameSite\s*:\s*["']none["'])/i, description: "Session-cookie configuration appears to weaken browser protections.", fix: "Set HttpOnly and Secure, choose an appropriate SameSite policy, and scope cookie domain and path narrowly.", cwe: "CWE-614", confidence: "Medium" },
  { id: "AUTH-009", title: "Weak or predictable session token", severity: "Medium", regex: /(?:session|auth|reset|verification)[_-]?token\s*[:=]\s*(?:Math\.random|random\.random|rand\s*\()/i, description: "A session or verification token may use a non-cryptographic random generator.", fix: "Generate tokens with a cryptographically secure random API and sufficient entropy.", cwe: "CWE-330", confidence: "Medium" },
  { id: "AUTH-010", title: "Missing rate-limit hint on authentication route", severity: "Low", regex: /(?:\/login|\/signin|\/forgot-password|\/reset-password)/i, description: "An authentication-related route is present. Static text matching cannot confirm whether rate limiting is implemented.", fix: "Verify server-side throttling, progressive delays, abuse monitoring, and safe account-recovery controls are configured.", cwe: "CWE-307", confidence: "Low" },
  // Cryptography and randomness
  { id: "CRYPTO-001", title: "Non-cryptographic randomness", severity: "Medium", regex: /(?:Math\.random\s*\(|random\.random\s*\(|rand\s*\()[^\n]*(?:token|session|secret|nonce|reset|otp|password)/i, description: "General-purpose random generators are not designed for security-sensitive tokens or codes.", fix: "Use a cryptographically secure random generator such as crypto.randomBytes or crypto.getRandomValues.", cwe: "CWE-330", confidence: "Medium" },
  { id: "CRYPTO-002", title: "Deprecated or weak cryptographic primitive", severity: "High", regex: /(?:createCipher\s*\(|\bDES\b|\bRC4\b|\bMD5\b|\bSHA-1\b)/i, description: "A deprecated or weak cryptographic primitive is referenced. Context determines whether it protects sensitive data.", fix: "Use modern, vetted algorithms and authenticated encryption such as AES-GCM or ChaCha20-Poly1305 where appropriate.", cwe: "CWE-327", confidence: "Medium" },
  { id: "CRYPTO-003", title: "ECB block cipher mode", severity: "High", regex: /(?:AES\/ECB|MODE_ECB|Cipher\.getInstance\s*\(["']AES["']\))/i, description: "ECB mode can reveal patterns in encrypted data and is generally unsuitable for sensitive information.", fix: "Use an authenticated encryption mode such as AES-GCM with unique nonces.", cwe: "CWE-327", confidence: "Medium" },
  { id: "CRYPTO-004", title: "Hardcoded cryptographic key or IV", severity: "High", regex: /(?:encryption[_-]?key|secret[_-]?key|initialization[_-]?vector|\biv)\s*[:=]\s*(?:Buffer\.from\s*\()?\s*["'][^"']{8,}["']/i, description: "Cryptographic key or IV material appears to be hardcoded.", fix: "Generate keys securely, keep them in a secret manager, and use a unique nonce/IV as required by the algorithm.", cwe: "CWE-321", confidence: "Medium" },
  { id: "CRYPTO-005", title: "Insufficient TLS minimum version", severity: "Medium", regex: /(?:TLSv1|TLSv1_0|TLSv1_1|SSLv3|PROTOCOL_TLSv1)\b/i, description: "A legacy TLS/SSL protocol version is referenced and may permit outdated cryptographic protections.", fix: "Require TLS 1.2 or newer (prefer TLS 1.3 where supported) and disable obsolete protocol versions.", cwe: "CWE-326", confidence: "Medium" },
  // Web configuration and browser security
  { id: "WEB-001", title: "Overly permissive CORS policy", severity: "Medium", regex: /(?:Access-Control-Allow-Origin|allow_origins)\s*[:=]\s*["']\*["']/, description: "A wildcard origin can expose browser-accessible resources to any website, depending on credentials and endpoint behavior.", fix: "Allow only trusted origins needed by your application and review credentialed endpoints carefully.", cwe: "CWE-942" },
  { id: "WEB-002", title: "Debug mode enabled", severity: "Medium", regex: /\bDEBUG\s*=\s*True\b|\bdebug\s*:\s*true\b/i, description: "Debug settings may expose stack traces, internal details, or interactive debugging features in production.", fix: "Disable debug mode in production and load the setting from deployment-specific configuration.", cwe: "CWE-489" },
  { id: "WEB-003", title: "Permissive content security policy", severity: "Medium", regex: /(?:Content-Security-Policy|contentSecurityPolicy)[^\n]*(?:unsafe-inline|unsafe-eval|default-src\s+\*)/i, description: "A CSP directive permits inline scripts, eval, or broad sources, reducing its ability to limit script injection.", fix: "Use nonces or hashes, avoid unsafe-eval, and restrict script sources to trusted origins.", cwe: "CWE-693", confidence: "Medium" },
  { id: "WEB-004", title: "Clickjacking protection disabled", severity: "Medium", regex: /(?:X-Frame-Options\s*[:=]\s*["']?ALLOWALL|frame-ancestors\s+\*)/i, description: "The configuration may allow untrusted sites to embed the application in a frame.", fix: "Set a restrictive frame-ancestors CSP and/or X-Frame-Options where appropriate.", cwe: "CWE-1021", confidence: "Medium" },
  { id: "WEB-005", title: "CSRF protection explicitly disabled", severity: "High", regex: /(?:csrf|xsrf)[^\n]*(?:enabled\s*[:=]\s*false|disable\s*\(|protect\s*:\s*false)/i, description: "A CSRF-related protection appears to be disabled.", fix: "Enable framework CSRF defenses for cookie-authenticated state-changing requests and validate origin where appropriate.", cwe: "CWE-352", confidence: "Medium" },
  { id: "WEB-006", title: "Insecure cookie configuration", severity: "Medium", regex: /(?:secure\s*:\s*false|httpOnly\s*:\s*false|httponly\s*=\s*False)/i, description: "Cookie settings explicitly disable a browser security attribute.", fix: "Enable Secure and HttpOnly for session cookies and set an appropriate SameSite policy.", cwe: "CWE-614", confidence: "Medium" },
  { id: "WEB-007", title: "Wildcard host binding", severity: "Low", regex: /(?:host|hostname|bind)\s*[:=]\s*["']0\.0\.0\.0["']/i, description: "The service listens on all IPv4 interfaces. This may be intended in containers but should be reviewed against network exposure.", fix: "Bind to the required interface and restrict exposure with firewall, container, or platform network policy.", cwe: "CWE-668", confidence: "Medium" },
  // Uploads, permissions, and filesystem
  { id: "FILE-001", title: "File upload may trust client filename", severity: "High", regex: /(?:save|writeFile|upload|move_uploaded_file)\s*\([^\n]*(?:originalname|filename|file\.name|client_name)/i, description: "An upload path may use a filename supplied by the client.", fix: "Generate a server-side filename, validate file content and size, store outside the web root, and prevent executable permissions.", cwe: "CWE-434", confidence: "Medium" },
  { id: "FILE-002", title: "Temporary file created insecurely", severity: "Medium", regex: /(?:tmpnam|tempnam|mktemp)\s*\(/i, description: "A temporary-file API may expose race conditions or predictable paths depending on its implementation.", fix: "Use secure temporary-file APIs that atomically create files with restrictive permissions.", cwe: "CWE-377", confidence: "Medium" },
  { id: "FILE-003", title: "Overly broad file permissions", severity: "Medium", regex: /(?:chmod\s*\([^\n]*0?777|chmod\s+777|mode\s*:\s*0o?777)/i, description: "World-readable, writable, or executable permissions may expose files or allow unintended modification.", fix: "Apply least-privilege permissions and grant only the access required by the process.", cwe: "CWE-732", confidence: "Medium" },
  { id: "FILE-004", title: "Sensitive file path exposed", severity: "Medium", regex: /(?:\.env|id_rsa|\.git\/config|credentials\.json|service-account\.json)/i, description: "A sensitive file path is referenced. Verify the file is not served publicly or included in a client bundle.", fix: "Keep secrets and repository metadata outside public roots and exclude them from build artifacts and deployment packages.", cwe: "CWE-552", confidence: "Medium" },
  // Cloud, containers, CI/CD and infrastructure as code
  { id: "CLOUD-001", title: "Terraform resource may be publicly accessible", severity: "High", regex: /(?:publicly_accessible|public_access|acl)\s*=\s*(?:true|"public-read")/i, description: "An infrastructure setting may expose a resource publicly. Confirm the resource type and intended access.", fix: "Disable public access unless required, use least-privilege policies, and add a deployment policy check.", cwe: "CWE-668", confidence: "Medium" },
  { id: "CLOUD-002", title: "Cloud storage public access enabled", severity: "High", regex: /(?:BlockPublicAcls|BlockPublicPolicy|ignore_public_acls|restrict_public_buckets)\s*=\s*false/i, description: "A cloud storage guardrail appears disabled and may allow public exposure.", fix: "Enable public-access blocks and review bucket/container policies and object ACLs.", cwe: "CWE-732", confidence: "Medium" },
  { id: "CLOUD-003", title: "Network ingress open to the internet", severity: "High", regex: /(?:cidr_blocks|source_ranges|ipBlock)[^\n]*(?:0\.0\.0\.0\/0|::\/0)/i, description: "A network rule appears to allow traffic from any IPv4 or IPv6 address.", fix: "Restrict ingress to required source ranges and expose only necessary ports.", cwe: "CWE-284", confidence: "Medium" },
  { id: "CLOUD-004", title: "Container runs in privileged mode", severity: "High", regex: /(?:privileged\s*:\s*true|--privileged)/i, description: "A container may be granted elevated host capabilities.", fix: "Remove privileged mode, drop unnecessary Linux capabilities, and enable a restrictive security profile.", cwe: "CWE-250", confidence: "Medium" },
  { id: "CLOUD-005", title: "Container image uses floating latest tag", severity: "Medium", regex: /\bimage\s*:\s*["']?[\w.\/-]+:latest\b/i, description: "A floating image tag makes deployments less reproducible and can unexpectedly change the software being run.", fix: "Pin a specific version or immutable digest and rebuild through a controlled update process.", cwe: "CWE-829", confidence: "Medium" },
  { id: "CLOUD-006", title: "Kubernetes container may run as root", severity: "High", regex: /runAsNonRoot\s*:\s*false|runAsUser\s*:\s*0\b/, description: "The workload may run as root inside the container, increasing impact if compromised.", fix: "Run as a non-root UID, set runAsNonRoot: true, and apply a restricted pod security standard.", cwe: "CWE-250", confidence: "Medium" },
  { id: "CLOUD-007", title: "GitHub Actions workflow uses unpinned action", severity: "Medium", regex: /uses\s*:\s*[\w.-]+\/[\w.-]+@(?:main|master|latest)\b/i, description: "A CI action tracks a mutable branch or tag, so its code can change without a reviewed commit.", fix: "Pin third-party actions to a verified full commit SHA and update them through reviewed dependency updates.", cwe: "CWE-829", confidence: "Medium" },
  { id: "CLOUD-008", title: "CI workflow grants broad write permissions", severity: "High", regex: /permissions\s*:\s*write-all/i, description: "A workflow may receive broad write permissions that increase the impact of compromised actions or pull requests.", fix: "Set least-privilege workflow and job permissions explicitly, granting write access only where needed.", cwe: "CWE-250", confidence: "Medium" },
  { id: "CLOUD-009", title: "Docker container may run as root", severity: "Medium", regex: /^\s*USER\s+root\s*$/i, description: "The Dockerfile explicitly switches to root, which can increase container compromise impact.", fix: "Create and use a dedicated non-root user for the runtime stage unless root is strictly required.", cwe: "CWE-250", confidence: "Medium" },
  { id: "CLOUD-010", title: "Kubernetes hostPath mount present", severity: "High", regex: /hostPath\s*:/, description: "A hostPath mount exposes host filesystem paths to a pod and can bypass intended isolation.", fix: "Avoid hostPath where possible; use narrowly scoped mounts and read-only access when required.", cwe: "CWE-668", confidence: "Medium" },
  // Dependencies and operational hygiene
  { id: "DEP-001", title: "Dependency version is floating", severity: "Low", regex: /(?:"[^"\n]+"\s*:\s*|version\s*[:=]\s*)["']?(?:\*|latest|>=\s*0)["']?/i, description: "A dependency declaration may not pin a reproducible version. Context varies by manifest format.", fix: "Use a lockfile, pin versions where appropriate, and run automated dependency vulnerability checks in CI.", cwe: "CWE-1104", confidence: "Low" },
  { id: "DEP-002", title: "Potentially unsafe package install script", severity: "Medium", regex: /(?:curl|wget)\s+[^\n]*(?:\|\s*(?:sh|bash)|\|\s*sudo)/i, description: "A downloaded script appears to be piped directly into a shell without an integrity check.", fix: "Download and inspect scripts, verify checksums/signatures, pin versions, and run installers with least privilege.", cwe: "CWE-494", confidence: "Medium" },
  { id: "DEP-003", title: "TLS verification bypass in package or HTTP client", severity: "High", regex: /(?:NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']0["']|PIP_TRUSTED_HOST\s*=|GIT_SSL_NO_VERIFY\s*=\s*true)/i, description: "An environment setting may disable transport security checks for tooling or application requests.", fix: "Remove the bypass and fix the certificate trust chain or proxy configuration instead.", cwe: "CWE-295", confidence: "Medium" },
  { id: "OPS-001", title: "Verbose exception details may be exposed", severity: "Medium", regex: /(?:send|response\.json|return)\s*\([^\n]*(?:err\.stack|exception\.stack|traceback\.format_exc|str\(e\))/i, description: "Internal exception details may be returned to a client and reveal implementation information.", fix: "Return generic client errors with a correlation ID; keep detailed traces in protected server logs.", cwe: "CWE-209", confidence: "Medium" },
  { id: "OPS-002", title: "Dangerous process termination or panic in request path", severity: "Low", regex: /(?:process\.exit\s*\(|os\._exit\s*\(|panic\s*\()/, description: "A process-wide termination call appears in the code and may disrupt service if reachable from request handling.", fix: "Handle errors at the request boundary and reserve process termination for controlled startup or shutdown paths.", cwe: "CWE-248", confidence: "Low" },
  { id: "OPS-003", title: "Wildcard host trust configuration", severity: "Medium", regex: /(?:trusted_hosts|allowed_hosts|ALLOWED_HOSTS)\s*[:=]\s*\[[^\]]*["']\*["']/i, description: "A host validation setting may trust every host, depending on framework semantics.", fix: "Configure explicit production hostnames and test rejection of unexpected Host headers.", cwe: "CWE-346", confidence: "Medium" },
];

const severityRank: Record<Severity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1 };
const severityColor: Record<Severity, string> = { Critical: "critical", High: "high", Medium: "medium", Low: "low" };
const extensions = /(?:\.(c|cc|cpp|cs|css|go|html?|java|js|jsx|json|kt|php|py|rb|rs|sh|sql|ts|tsx|xml|ya?ml|env|toml|ini|tf|hcl|dockerfile|properties|gradle|lock)|(^|\/)Dockerfile|\.github\/workflows\/[^/]+\.ya?ml)$/i;

function scanSources(files: SourceFile[]): Finding[] {
  const found: Finding[] = [];
  for (const file of files) {
    const lines = file.content.split(/\r?\n/);
    lines.forEach((line, index) => {
      for (const rule of RULES) {
        rule.regex.lastIndex = 0;
        if (rule.regex.test(line)) {
          const id = `${file.name}:${index + 1}:${rule.id}`;
          if (!found.some((item) => item.id === id)) found.push({
            id, rule: rule.id, title: rule.title, severity: rule.severity, file: file.name,
            line: index + 1, snippet: line.trim().slice(0, 180), description: rule.description,
            fix: rule.fix, cwe: rule.cwe, confidence: rule.confidence ?? "High",
          });
        }
      }
    });
  }
  return found.sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || a.line - b.line);
}


function CodeCookApp() {
  const [mode, setMode] = useState<"code" | "links">("code");
  const [linksText, setLinksText] = useState("https://bit.ly/verify-account-now\nhttp://192.0.2.10/login-confirm\nhttps://accounts.example.com.security-check.click/claim-free-prize");
  const [files, setFiles] = useState<SourceFile[]>([]);
  const [activeFile, setActiveFile] = useState("");
  const [code, setCode] = useState("");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scanned, setScanned] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [filter, setFilter] = useState("All findings");
  const [selected, setSelected] = useState<string | null>(null);
  const [mobileNav, setMobileNav] = useState(false);
  const [notice, setNotice] = useState("");
  const [uploadIssues, setUploadIssues] = useState<UploadIssue[]>([]);
  const fileInput = useRef<HTMLInputElement>(null);
  const folderInput = useRef<HTMLInputElement>(null);
  const zipInput = useRef<HTMLInputElement>(null);

  const visibleFindings = useMemo(() => filter === "All findings" ? findings : findings.filter((f) => f.severity === filter), [findings, filter]);
  const selectedFinding = findings.find((f) => f.id === selected) ?? visibleFindings[0] ?? null;
  const counts = useMemo(() => ({
    Critical: findings.filter((f) => f.severity === "Critical").length,
    High: findings.filter((f) => f.severity === "High").length,
    Medium: findings.filter((f) => f.severity === "Medium").length,
    Low: findings.filter((f) => f.severity === "Low").length,
  }), [findings]);

  async function readFiles(list: FileList | File[]) {
    const selected = Array.from(list);
    const issues: UploadIssue[] = [];
    const accepted: Array<{ file: File; name: string }> = [];
    let totalBytes = 0;
    for (const file of selected) {
      const name = (file.webkitRelativePath || file.name).replace(/\\/g, "/");
      if (!extensions.test(name)) { issues.push({ id: `${name}:extension`, file: name, reason: "Unsupported file type. Choose a source/config file such as .js, .ts, .py, .java, .php, .json, .yaml, Dockerfile, or .env." }); continue; }
      if (file.size > 1024 * 1024) { issues.push({ id: `${name}:size`, file: name, reason: `File is ${(file.size / (1024 * 1024)).toFixed(2)} MB; the per-file limit is 1 MB.` }); continue; }
      if (accepted.length >= 100) { issues.push({ id: `${name}:count`, file: name, reason: "File limit reached: at most 100 source files can be scanned in one batch." }); break; }
      if (totalBytes + file.size > 20 * 1024 * 1024) { issues.push({ id: `${name}:total`, file: name, reason: "Batch size limit reached: total source content must not exceed 20 MB." }); continue; }
      accepted.push({ file, name }); totalBytes += file.size;
    }
    const loaded: SourceFile[] = [];
    for (const item of accepted) {
      try { loaded.push({ name: item.name, content: await item.file.text() }); }
      catch (error) { issues.push({ id: `${item.name}:read`, file: item.name, reason: `Browser could not read this file: ${error instanceof Error ? error.message : "unknown read error"}` }); }
    }
    if (loaded.length) {
      setFiles((old) => {
        const merged = new Map(old.map((f) => [f.name, f]));
        for (const file of loaded) merged.set(file.name, file);
        return Array.from(merged.values()).slice(-100);
      });
      setActiveFile(loaded[0].name); setCode(loaded[0].content); setFindings([]); setScanned(false);
    }
    setUploadIssues(issues.slice(0, 100));
    if (loaded.length && !issues.length) setNotice(`${loaded.length} source file${loaded.length === 1 ? "" : "s"} loaded locally, preserving folder paths. Your code has not been uploaded to a server.`);
    else if (loaded.length) setNotice(`${loaded.length} file${loaded.length === 1 ? "" : "s"} loaded; ${issues.length} item${issues.length === 1 ? " was" : "s were"} skipped. See upload diagnostics below.`);
    else setNotice(issues.length ? `No supported files loaded. ${issues.length} upload issue${issues.length === 1 ? "" : "s"} found; details are listed below.` : "No files were selected.");
  }

  async function readZip(file?: File) {
    if (!file) return;
    if (file.size > 20 * 1024 * 1024) {
      const issue = { id: `${file.name}:zip-size`, file: file.name, reason: "ZIP archive is larger than the 20 MB upload limit." };
      setUploadIssues([issue]); setNotice(`Upload failed: ${issue.reason}`); return;
    }
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const entries = inspectZipDirectory(bytes);
      const archiveIssues: UploadIssue[] = [];
      if (!entries.length) throw new Error("The ZIP archive contains no readable file entries.");
      if (entries.length > 500) throw new Error("The ZIP contains more than 500 entries; split it into smaller archives.");
      const totalExpanded = entries.reduce((sum, entry) => sum + entry.uncompressedSize, 0);
      if (totalExpanded > 20 * 1024 * 1024) throw new Error("The expanded ZIP content exceeds the 20 MB safety limit.");
      for (const entry of entries) {
        if (entry.encrypted) throw new Error(`Encrypted ZIP entry cannot be scanned: ${entry.name}`);
        if (entry.uncompressedSize > 1024 * 1024) archiveIssues.push({ id: `${entry.name}:size`, file: entry.name, reason: `Expanded file is ${(entry.uncompressedSize / (1024 * 1024)).toFixed(2)} MB; the per-file limit is 1 MB.` });
        else if (!extensions.test(entry.name)) archiveIssues.push({ id: `${entry.name}:extension`, file: entry.name, reason: "Unsupported file type inside ZIP; this entry was skipped." });
      }
      const extracted = unzipSync(bytes);
      const loaded: SourceFile[] = [];
      for (const entry of entries) {
        if (entry.uncompressedSize > 1024 * 1024 || !extensions.test(entry.name)) continue;
        const content = extracted[entry.name];
        if (!content) continue;
        loaded.push({ name: entry.name, content: strFromU8(content) });
        if (loaded.length >= 100) { archiveIssues.push({ id: `${file.name}:count`, file: file.name, reason: "Only the first 100 supported source files were loaded from this ZIP." }); break; }
      }
      if (!loaded.length) throw new Error("No supported source files were found. The ZIP may contain only binaries, unsupported extensions, or files larger than 1 MB.");
      setFiles(loaded); setActiveFile(loaded[0].name); setCode(loaded[0].content); setFindings([]); setScanned(false);
      setUploadIssues(archiveIssues.slice(0, 100));
      setNotice(`${loaded.length} source file${loaded.length === 1 ? "" : "s"} extracted from ${file.name} in your browser. No code was sent to a server.${archiveIssues.length ? ` ${archiveIssues.length} archive entr${archiveIssues.length === 1 ? "y was" : "ies were"} skipped; review diagnostics.` : ""}`);
    } catch (error) {
      const reason = error instanceof Error ? error.message : "The archive could not be read.";
      const issue = { id: `${file.name}:zip-invalid`, file: file.name, reason: `ZIP import failed: ${reason}` };
      setUploadIssues([issue]); setNotice(issue.reason);
    }
  }

  function inspectZipDirectory(bytes: Uint8Array): Array<{ name: string; uncompressedSize: number; encrypted: boolean }> {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const lowerBound = Math.max(0, bytes.length - 65557);
    let eocd = -1;
    for (let i = bytes.length - 22; i >= lowerBound; i--) if (view.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    if (eocd < 0) throw new Error("Invalid ZIP structure: end-of-central-directory record was not found.");
    const count = view.getUint16(eocd + 10, true);
    const directoryOffset = view.getUint32(eocd + 16, true);
    if (count === 0xffff || directoryOffset === 0xffffffff) throw new Error("ZIP64 archives are not supported yet; create a standard ZIP archive.");
    if (count > 500) throw new Error("ZIP contains more than 500 entries; split it into smaller archives.");
    const result: Array<{ name: string; uncompressedSize: number; encrypted: boolean }> = [];
    let offset = directoryOffset;
    for (let i = 0; i < count; i++) {
      if (offset + 46 > bytes.length || view.getUint32(offset, true) !== 0x02014b50) throw new Error("Invalid ZIP central directory entry.");
      const flags = view.getUint16(offset + 8, true);
      const compressedSize = view.getUint32(offset + 20, true);
      const uncompressedSize = view.getUint32(offset + 24, true);
      const nameLength = view.getUint16(offset + 28, true);
      const extraLength = view.getUint16(offset + 30, true);
      const commentLength = view.getUint16(offset + 32, true);
      const nameBytes = bytes.slice(offset + 46, offset + 46 + nameLength);
      const rawName = strFromU8(nameBytes, !(flags & 0x0800));
      const name = rawName.replace(/\\/g, "/");
      if (name.startsWith("/") || /^[a-zA-Z]:/.test(name) || name.split("/").includes("..")) throw new Error(`Unsafe path in ZIP rejected: ${rawName}`);
      if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff) throw new Error("ZIP64 entries are not supported yet.");
      if (uncompressedSize > 20 * 1024 * 1024) throw new Error(`Entry is too large to safely inspect: ${name}`);
      if (!name.endsWith("/")) result.push({ name, uncompressedSize, encrypted: Boolean(flags & 1) });
      offset += 46 + nameLength + extraLength + commentLength;
    }
    return result;
  }

  function updateCode(next: string) {
    setCode(next);
    setFiles((old) => {
      if (!activeFile) return [{ name: "pasted-code.js", content: next }];
      if (!old.some((f) => f.name === activeFile)) return [...old, { name: activeFile, content: next }];
      return old.map((f) => f.name === activeFile ? { ...f, content: next } : f);
    });
    setScanned(false);
  }

  function loadSample() {
    const demo = [{ name: "sample-app.py", content: SAMPLE }];
    setFiles(demo); setActiveFile(demo[0].name); setCode(SAMPLE); setFindings([]); setScanned(false); setNotice("Sample loaded. Run the scan to see how findings and remediation work.");
  }

  async function runScan() {
    const current = files.length ? files.map((f) => f.name === activeFile ? { ...f, content: code } : f) : (code.trim() ? [{ name: "pasted-code.js", content: code }] : []);
    if (mode === "code" && (!current.length || !current.some((f) => f.content.trim()))) { setNotice("Upload a code file, paste code, or load the sample first."); return; }
    if (mode === "links" && !linksText.trim()) { setNotice("Paste one URL per line to check for suspicious link patterns."); return; }
    setScanning(true); setNotice("");
    await new Promise((resolve) => setTimeout(resolve, 300));
    const results = mode === "links" ? scanSpamLinks(linksText) : scanSources(current);
    setFindings(results); setScanned(true); setSelected(results[0]?.id ?? null); setScanning(false);
    setNotice(results.length ? `${mode === "links" ? "Link check" : "Code scan"} complete. ${results.length} potential risk signal${results.length === 1 ? "" : "s"} need review.` : `${mode === "links" ? "Link check" : "Scan"} complete. No matching risk signals were found. This is not a guarantee of safety.`);
  }

  function downloadReport() {
    const report = { product: "CodeCook", generatedAt: new Date().toISOString(), scanType: mode === "links" ? "Local heuristic spam-link check (no reputation lookup or network requests)" : "Local static pattern scan", filesScanned: mode === "links" ? ["pasted-links.txt"] : files.map((f) => f.name), summary: counts, findings };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = "codecook-security-report.json"; a.click(); URL.revokeObjectURL(url);
  }

  async function copyFix(fix: string) {
    try { await navigator.clipboard.writeText(fix); setNotice("Remediation guidance copied."); }
    catch { setNotice("Clipboard access is unavailable. Select and copy the remediation text manually."); }
  }

  function goToScanner() { document.getElementById("scanner")?.scrollIntoView({ behavior: "smooth", block: "start" }); }

  return (
    <div className="codecook-shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="CodeCook home"><span className="brand-mark"><ShieldCheck size={22} strokeWidth={2.2} /></span><span>CodeCook<span className="brand-period">.</span></span></a>
        <nav className={mobileNav ? "nav-links nav-open" : "nav-links"} aria-label="Main navigation">
          <a href="#how-it-works" onClick={() => setMobileNav(false)}>How it works</a><a href="#scanner" onClick={() => setMobileNav(false)}>Scanner</a><a href="#security" onClick={() => setMobileNav(false)}>Privacy</a>
        </nav>
        <div className="top-actions"><span className="local-pill"><span className="live-dot" /> Runs in your browser</span><button className="nav-cta" onClick={goToScanner}>Open scanner <ArrowUpRight size={15} /></button></div>
        <button className="mobile-menu" onClick={() => setMobileNav(!mobileNav)} aria-label="Toggle navigation">{mobileNav ? <X /> : <Menu />}</button>
      </header>

      <main id="top">
        <section className="hero-section">
          <div className="hero-copy">
            <div className="eyebrow"><span className="eyebrow-icon"><Radar size={14} /></span> SECURITY THAT SPEAKS DEVELOPER</div>
            <h1>Ship code.<br /><span className="headline-accent">Not vulnerabilities.</span></h1>
            <p className="hero-subtitle">A privacy-first security workspace for source-code risk checks and suspicious-link analysis. Inspect common warning signs without sending code or opening links.</p>
            <div className="hero-buttons"><button className="button-primary" onClick={goToScanner}>Start a free scan <ArrowRight size={17} /></button><a className="button-secondary" href="#how-it-works"><span className="play-icon"><Play size={12} fill="currentColor" /></span> See how it works</a></div>
            <div className="hero-proof"><div className="proof-item"><LockKeyhole size={15} /><span>Code & links stay local</span></div><span className="proof-separator" /><div className="proof-item"><Zap size={15} /><span>No API key needed</span></div><span className="proof-separator" /><div className="proof-item"><Code2 size={15} /><span>Developer-first</span></div></div>
          </div>
          <div className="hero-visual" aria-label="Abstract three dimensional security shield illustration">
            <div className="visual-orbit orbit-one" /><div className="visual-orbit orbit-two" /><div className="visual-orbit orbit-three" />
            <div className="visual-cross cross-a" /><div className="visual-cross cross-b" />
            <div className="shield-stage"><div className="shield-shadow" /><div className="shield-glass"><div className="shield-inner"><Shield size={76} strokeWidth={1.15} /><span className="shield-check"><Check size={29} strokeWidth={2.5} /></span></div></div><div className="shield-base" /></div>
            <div className="float-chip chip-top"><span className="chip-icon chip-green"><ShieldCheck size={15} /></span><span><strong>Private by design</strong><small>Local analysis</small></span></div>
            <div className="float-chip chip-bottom"><span className="chip-icon chip-coral"><ScanSearch size={15} /></span><span><strong>Risk detected</strong><small>Understand. Fix. Verify.</small></span><span className="chip-arrow"><ArrowUpRight size={14} /></span></div>
            <div className="visual-caption"><span className="caption-line" /> BUILT FOR THE NEXT COMMIT</div>
          </div>
        </section>

        <section className="trust-strip" aria-label="Product principles"><div><Fingerprint size={17} /><span>Local-first scanning</span></div><div><ShieldCheck size={17} /><span>Actionable findings</span></div><div><Terminal size={17} /><span>Made for real code</span></div><div><BadgeCheck size={17} /><span>Free to try</span></div></section>

        <section className="scanner-section" id="scanner">
          <div className="section-heading"><div><div className="eyebrow section-eyebrow">THE SECURITY WORKSPACE</div><h2>Find the weak spots.</h2><p>Scan code for risky patterns or check suspicious URLs for phishing-style signals. Both tools run locally in your browser.</p></div><div className="workspace-tag"><span className="live-dot" /> {RULES.length} DETECTION RULES</div></div>
          <div className="coverage-chips" aria-label="Detection categories">{["Secrets", "Injection", "Auth & sessions", "Network", "Files", "Cryptography", "Web config", "Cloud & CI/CD", "Dependencies"].map((category) => <span key={category}>{category}</span>)}</div>
          <div className="scanner-workspace">
            <div className="workspace-topline"><div className="window-controls"><i /><i /><i /></div><div className="workspace-title"><span className="workspace-title-icon">{mode === "code" ? <Code2 size={14} /> : <Link2 size={14} />}</span> {mode === "code" ? "Code security workspace" : "Spam link checker"}</div><div className="workspace-top-right"><span className="encrypted-label"><LockKeyhole size={12} /> LOCAL ONLY</span></div></div>
            <div className="scan-mode-switch" role="tablist" aria-label="Choose scan type">
              <button role="tab" aria-selected={mode === "code"} className={mode === "code" ? "mode-tab active" : "mode-tab"} onClick={() => { setMode("code"); setFindings([]); setScanned(false); setNotice(""); }}><Code2 size={15} /> Code security</button>
              <button role="tab" aria-selected={mode === "links"} className={mode === "links" ? "mode-tab active" : "mode-tab"} onClick={() => { setMode("links"); setFindings([]); setScanned(false); setNotice(""); }}><Link2 size={15} /> Spam link check <span className="new-feature-badge">NEW</span></button>
            </div>
            {mode === "code" ? <div className="workspace-body">
              <aside className="file-rail"><div className="rail-heading"><span>PROJECT FILES</span><button onClick={() => fileInput.current?.click()} title="Add code files"><Upload size={14} /></button></div><input ref={fileInput} type="file" accept=".c,.cc,.cpp,.cs,.css,.go,.html,.htm,.java,.js,.jsx,.json,.kt,.php,.py,.rb,.rs,.sh,.sql,.ts,.tsx,.xml,.yaml,.yml,.env,.toml,.ini,.tf,.hcl,.dockerfile,.properties,.gradle,.lock" multiple hidden onChange={(e) => { if (e.target.files) void readFiles(e.target.files); e.currentTarget.value = ""; }} /><input ref={folderInput} type="file" multiple hidden onChange={(e) => { if (e.target.files) void readFiles(e.target.files); e.currentTarget.value = ""; }} {...({ webkitdirectory: "", directory: "" } as Record<string, string>)} /><input ref={zipInput} type="file" accept=".zip,application/zip,application/x-zip-compressed" hidden onChange={(e) => { void readZip(e.target.files?.[0]); e.currentTarget.value = ""; }} />
              {files.length ? <div className="file-list">{files.map((f) => <button key={f.name} className={activeFile === f.name ? "file-item active" : "file-item"} onClick={() => { setActiveFile(f.name); setCode(f.content); }}><FileCode2 size={14} /><span>{f.name}</span>{findings.some((x) => x.file === f.name) && <i className="file-alert" />}</button>)}</div> : <button className="empty-files" onClick={() => fileInput.current?.click()}><FileUp size={21} /><span>No files yet</span><small>Upload to begin</small></button>}
              <div className="rail-upload-actions"><button className="rail-upload" onClick={() => fileInput.current?.click()}><Upload size={14} /> Files</button><button className="rail-upload" onClick={() => folderInput.current?.click()}><FileCode2 size={14} /> Folder</button><button className="rail-upload" onClick={() => zipInput.current?.click()}><ArrowDownToLine size={14} /> ZIP</button></div><div className="rail-bottom"><div className="rail-lock"><LockKeyhole size={14} /><span>Private workspace</span></div><p>Files are read locally and are not sent to a server.</p></div></aside>
              <div className="editor-pane"><div className="editor-toolbar"><div className="editor-tab"><span className="language-dot" />{activeFile || "untitled.js"}<span className="unsaved-dot" /></div><div className="editor-actions"><button onClick={loadSample}><Sparkles size={13} /> Load sample</button><button onClick={() => { setCode(""); setFiles([]); setActiveFile(""); setFindings([]); setScanned(false); setNotice(""); setUploadIssues([]); }} title="Clear editor"><X size={14} /></button></div></div>
              <div className="code-editor"><div className="line-numbers" aria-hidden="true">{(code || " ").split("\n").map((_, i) => <span key={i}>{i + 1}</span>)}</div><textarea aria-label="Paste source code to scan" spellCheck={false} value={code} onChange={(e) => updateCode(e.target.value)} placeholder={'// Paste your source code here\n// or upload files from the left panel\n\nfunction secureYourApp() {\n  // Your code, your browser.\n}'} /></div>
              <div className="editor-footer"><span><span className="status-dot" /> {code ? `${code.split("\n").length} lines` : "Ready for source code"}</span><span>{new TextEncoder().encode(code).length.toLocaleString()} bytes</span></div>
              </div>
            </div> : <div className="link-checker-panel">
              <div className="link-checker-intro"><div className="link-checker-icon"><Globe size={22} /></div><div><h3>Check suspicious links before you open them</h3><p>Paste one URL per line. CodeCook checks visible URL patterns locally; it does not open links or contact the destination.</p></div></div>
              <label className="link-input-label" htmlFor="links-input"><span>URL LIST</span><span>{linksText.split(/\r?\n/).filter((line) => line.trim()).length} entries</span></label>
              <textarea id="links-input" className="links-textarea" spellCheck={false} value={linksText} onChange={(e) => { setLinksText(e.target.value); setScanned(false); }} placeholder={'https://example.com/login\nhttps://bit.ly/suspicious-offer\nexample.org/verify-account'} />
              <div className="link-tool-footer"><span><LockKeyhole size={14} /> Runs locally · No network lookup</span><button onClick={() => setLinksText("https://bit.ly/verify-account-now\nhttp://192.0.2.10/login-confirm\nhttps://accounts.example.com.security-check.click/claim-free-prize")}><Sparkles size={14} /> Load test links</button></div>
              <div className="link-signal-grid"><div><SearchCheck size={16} /><span>Lookalike & punycode</span></div><div><ExternalLink size={16} /><span>Shorteners & redirects</span></div><div><ShieldAlert size={16} /><span>Phishing-style wording</span></div><div><ListChecks size={16} /><span>URL structure signals</span></div></div>
            </div>}
            <div className="scan-toolbar"><div className="scan-method"><Shield size={15} /><span>{mode === "code" ? `Local static analysis · ${RULES.length} rules` : "Local URL heuristics · 13 signals"}</span><span className="scan-method-badge">NO KEY</span></div><button className="run-scan" onClick={() => void runScan()} disabled={scanning}>{scanning ? <><span className="button-spinner" /> Checking…</> : <><Play size={14} fill="currentColor" /> {mode === "code" ? "Run security scan" : "Check links"}</>}</button></div>
            <div className="workspace-footnote"><CircleHelp size={13} /><span>Local rule-based checks cover common risky patterns, but can miss context-dependent flaws or flag safe code. Review each finding before changing production code.</span></div>
          </div>
          {notice && <div className="notice-line" role="status"><span className="notice-symbol"><Activity size={15} /></span>{notice}</div>}
          {uploadIssues.length > 0 && <section className="upload-diagnostics" aria-label="Upload diagnostics"><div className="upload-diagnostics-head"><strong>Upload diagnostics</strong><span>{uploadIssues.length} issue{uploadIssues.length === 1 ? "" : "s"}</span><button onClick={() => setUploadIssues([])}>Clear</button></div><div className="upload-diagnostics-list">{uploadIssues.map((issue) => <article key={issue.id} className="upload-diagnostic"><AlertTriangle size={15} /><div><strong>{issue.file}{issue.line ? ` · Line ${issue.line}` : " · Line N/A (upload/import issue)"}</strong><p>{issue.reason}</p></div></article>)}</div></section>}

          <div className="results-area" aria-live="polite">
            <div className="results-header"><div><div className="results-overline">{mode === "links" ? "LINK CHECK RESULTS" : "SCAN RESULTS"}</div><h3>{scanned ? (findings.length ? `${findings.length} potential ${mode === "links" ? "risk signals" : "issues"} found` : "No matching patterns found") : "Your findings will appear here"}</h3><p>{scanned ? (mode === "links" ? "These are heuristic warning signs, not a live reputation verdict. Review each URL carefully." : "Review the evidence and remediation guidance before you ship.") : (mode === "links" ? "Check URL structure for common phishing and spam signals without opening the links." : "Run a scan to see severity, code context, and suggested next steps.")}</p></div>{scanned && <button className="report-button" onClick={downloadReport}><ArrowDownToLine size={15} /> Export JSON report</button>}</div>
            <div className="metrics-row"><div className="metric-card metric-total"><span className="metric-icon"><Radar size={16} /></span><span className="metric-number">{scanned ? findings.length : "—"}</span><span className="metric-label">Total findings</span></div><div className="metric-card"><span className="metric-icon metric-red"><AlertOctagon size={16} /></span><span className="metric-number">{scanned ? counts.Critical : "—"}</span><span className="metric-label">Critical</span></div><div className="metric-card"><span className="metric-icon metric-orange"><AlertTriangle size={16} /></span><span className="metric-number">{scanned ? counts.High : "—"}</span><span className="metric-label">High risk</span></div><div className="metric-card"><span className="metric-icon metric-yellow"><Activity size={16} /></span><span className="metric-number">{scanned ? counts.Medium + counts.Low : "—"}</span><span className="metric-label">Medium / low</span></div></div>
            <div className="findings-layout"><div className="findings-list-panel"><div className="findings-list-head"><strong>Findings <span>{scanned ? findings.length : 0}</span></strong><div className="filter-wrap"><select aria-label="Filter findings by severity" value={filter} onChange={(e) => setFilter(e.target.value)}><option>All findings</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select><ChevronDown size={13} /></div></div>
              {visibleFindings.length ? <div className="finding-list">{visibleFindings.map((f) => <button key={f.id} className={selectedFinding?.id === f.id ? "finding-row selected" : "finding-row"} onClick={() => setSelected(f.id)}><span className={`severity-mark ${severityColor[f.severity]}`} /><span className="finding-row-copy"><strong>{f.title}</strong><small><span>{f.file}</span><span>Line {f.line}</span></small></span><span className={`severity-pill ${severityColor[f.severity]}`}>{f.severity}</span><ChevronRight size={15} className="finding-chevron" /></button>)}</div> : <div className="results-empty"><span className="empty-shield"><ShieldCheck size={26} /></span><strong>{scanned ? "Nothing matched these rules" : "No findings yet"}</strong><p>{scanned ? "Try another severity filter or scan a different file." : "Your code findings and their severity will show up after a scan."}</p>{!scanned && <button onClick={loadSample}>Try sample code <ArrowRight size={14} /></button>}</div>}
            </div>
            <div className="finding-detail-panel">{selectedFinding ? <><div className="detail-head"><span className={`severity-pill ${severityColor[selectedFinding.severity]}`}>{selectedFinding.severity} severity</span><span className="detail-rule">{selectedFinding.rule}</span></div><h4>{selectedFinding.title}</h4><div className="finding-reason"><strong>Reason / why this was flagged</strong><p className="detail-description">{selectedFinding.description}</p></div><div className="code-context"><div className="context-head"><span><FileCode2 size={13} /> {selectedFinding.file}</span><span>LINE {selectedFinding.line}</span></div><div className="context-code"><span className="context-line-number">{selectedFinding.line}</span><code>{selectedFinding.snippet || "(empty line)"}</code></div></div><div className="detail-meta"><span>Reference <strong>{selectedFinding.cwe}</strong></span><span>Confidence <strong>{selectedFinding.confidence}</strong></span></div><div className="fix-box"><div className="fix-heading"><span className="fix-icon"><Sparkles size={14} /></span><strong>Recommended fix</strong><span className="guidance-label">GUIDANCE</span></div><p>{selectedFinding.fix}</p><button onClick={() => void copyFix(selectedFinding.fix)}><Clipboard size={13} /> Copy remediation</button></div></> : <div className="detail-placeholder"><div className="detail-placeholder-icon"><ScanSearch size={24} /></div><strong>Finding details</strong><p>Select a finding to see its code context and remediation guidance.</p></div>}</div></div>
            <p className="results-disclaimer"><LockKeyhole size={13} /> CodeCook runs local rule-based code checks and heuristic URL analysis. It does not execute code, open links, or query a live threat-intelligence feed. No alert does not guarantee safety.</p>
          </div>
        </section>

        <section className="how-section" id="how-it-works"><div className="how-intro"><div className="eyebrow section-eyebrow">LESS GUESSING, SAFER SHIPPING</div><h2>Security should help<br />you move forward.</h2><p>Clear findings, useful context, and practical guidance. Built to fit the way developers already work.</p></div><div className="how-steps"><article className="how-step"><div className="step-number">01</div><div className="step-icon step-violet"><FileUp size={21} /></div><h3>Bring your code</h3><p>Upload supported source files or paste a snippet. No account or API key is required.</p><span className="step-note"><LockKeyhole size={12} /> Stays in your browser</span></article><article className="how-step"><div className="step-number">02</div><div className="step-icon step-coral"><ScanSearch size={21} /></div><h3>Understand the risk</h3><p>Review detected patterns, line numbers, severity, confidence, CWE references, and safer alternatives.</p><span className="step-note"><Radar size={12} /> Evidence-first results</span></article><article className="how-step"><div className="step-number">03</div><div className="step-icon step-green"><ShieldCheck size={21} /></div><h3>Fix with confidence</h3><p>Use actionable remediation guidance, then scan again to check whether the pattern remains.</p><span className="step-note"><Check size={12} /> Review before merging</span></article></div></section>

        <section className="privacy-section" id="security"><div className="privacy-art"><div className="privacy-ring ring-one" /><div className="privacy-ring ring-two" /><div className="privacy-lock"><LockKeyhole size={43} strokeWidth={1.4} /></div><div className="privacy-spark spark-one" /><div className="privacy-spark spark-two" /></div><div className="privacy-copy"><div className="eyebrow section-eyebrow">YOUR CODE IS YOURS</div><h2>Private by default.<br /><span>Useful by design.</span></h2><p>CodeCook reads the files you choose directly in your browser. It does not upload your source code to a scanning server, and it does not need a third-party AI key to run its built-in checks.</p><div className="privacy-points"><div><span><Check size={14} /></span> No account or API key required</div><div><span><Check size={14} /></span> Code is not executed</div><div><span><Check size={14} /></span> Export your report when you're ready</div></div><button className="button-primary" onClick={goToScanner}>Scan your code <ArrowRight size={16} /></button></div></section>

        <section className="closing-cta"><div className="closing-orb" /><div className="closing-content"><span className="closing-mark"><ShieldCheck size={24} /></span><h2>Make your next commit<br />a safer one.</h2><p>Start with a file. Leave with a clearer next step.</p><button className="closing-button" onClick={goToScanner}>Run your first scan <ArrowRight size={16} /></button></div></section>
      </main>

      <footer className="footer"><a className="brand footer-brand" href="#top"><span className="brand-mark"><ShieldCheck size={19} /></span><span>CodeCook<span className="brand-period">.</span></span></a><span className="footer-copy">Security is a practice, not a checkbox.</span><div className="footer-links"><a href="#how-it-works">How it works</a><a href="#security">Privacy</a><a href="#scanner">Open scanner <ArrowUpRight size={12} /></a></div><span className="footer-note">Built for safer code.</span></footer>
    </div>
  );
}
