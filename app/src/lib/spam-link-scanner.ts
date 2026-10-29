type LinkSeverity = "Critical" | "High" | "Medium" | "Low";
type LinkFinding = {
  id: string; rule: string; title: string; severity: LinkSeverity; file: string; line: number;
  snippet: string; description: string; fix: string; cwe: string; confidence: "High" | "Medium" | "Low";
};
const severityRank: Record<LinkSeverity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1 };

const SHORTENER_HOSTS = new Set(["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "buff.ly", "shorturl.at", "rebrand.ly", "lnkd.in", "soo.gd", "s.id"]);
const RISKY_TLDS = new Set(["zip", "mov", "click", "top", "work", "country", "gq", "tk", "ml", "cf", "rest", "fit"]);
const SUSPICIOUS_LINK_WORDS = /(?:verify[-_ ]?(?:account|identity)|account[-_ ]?(?:suspend|verify|locked)|password[-_ ]?reset|urgent[-_ ]?action|free[-_ ]?(?:gift|prize|crypto|money)|claim[-_ ]?(?:reward|prize)|wallet[-_ ]?connect|seed[-_ ]?phrase|airdrop|giveaway|login[-_ ]?confirm|billing[-_ ]?update)/i;

export function scanSpamLinks(input: string): LinkFinding[] {
  const findings: LinkFinding[] = [];
  const lines = input.split(/\r?\n/);
  const add = (line: number, url: string, rule: string, title: string, severity: LinkSeverity, description: string, fix: string, confidence: LinkFinding["confidence"] = "Medium") => {
    findings.push({ id: `links:${line}:${rule}:${url}`, rule, title, severity, file: "pasted-links.txt", line, snippet: url.slice(0, 180), description, fix, cwe: "Heuristic", confidence });
  };
  lines.forEach((raw, index) => {
    const candidate = raw.trim().replace(/^(?:[-*•]|\d+[.)])\s*/, "").replace(/[),.;]+$/, "");
    if (!candidate || candidate.startsWith("#")) return;
    const normalized = /^(?:https?:\/\/|ftp:\/\/)/i.test(candidate) ? candidate : `https://${candidate}`;
    let parsed: URL;
    try { parsed = new URL(normalized); } catch {
      add(index + 1, candidate, "LINK-000", "Malformed or unparseable link", "Medium", "This entry could not be parsed as a URL. It may be a typo, malformed address, or pasted non-link text.", "Check the spelling and URL structure manually. Do not open unknown links just to test them.", "High");
      return;
    }
    if (!["http:", "https:"].includes(parsed.protocol)) {
      add(index + 1, candidate, "LINK-001", "Unexpected URL protocol", "High", `The URL uses the ${parsed.protocol} protocol rather than ordinary web HTTP(S). Opening it may trigger a local application or another handler.`, "Do not open it unless you trust the sender and explicitly expect this protocol.", "High");
      return;
    }
    const host = parsed.hostname.toLowerCase().replace(/^www\./, "");
    if (parsed.username || parsed.password) add(index + 1, candidate, "LINK-002", "Credentials embedded in URL", "High", "The URL includes a username or password before the hostname. This pattern can disguise the real destination or expose credentials in logs.", "Remove embedded credentials and inspect the actual hostname before proceeding.", "High");
    if (host.startsWith("xn--") || host.split(".").some((part) => part.startsWith("xn--"))) add(index + 1, candidate, "LINK-003", "Punycode domain may imitate a trusted site", "High", "The hostname contains an internationalized Punycode label. This is not inherently malicious, but it can be used for lookalike-domain deception.", "Compare the domain with the organization's official domain and verify it through a trusted channel.", "Medium");
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || /^\[[0-9a-f:]+\]$/i.test(host)) add(index + 1, candidate, "LINK-004", "Link points directly to an IP address", "High", "The URL uses a raw IP address instead of a recognizable domain. This can be legitimate, but is common in disposable or deceptive links.", "Only continue if you expected this exact host and can independently verify its ownership.", "Medium");
    if (SHORTENER_HOSTS.has(host)) add(index + 1, candidate, "LINK-005", "URL shortener hides the destination", "Medium", "A URL-shortening service obscures the final destination in the visible link. Shorteners are common in legitimate messages too.", "Reveal the destination using a trusted link-expansion service or ask the sender for the original URL. Do not click to investigate.", "High");
    const tld = host.split(".").pop() || "";
    if (RISKY_TLDS.has(tld)) add(index + 1, candidate, "LINK-006", "Domain uses a higher-risk TLD", "Low", `The domain ends in .${tld}. TLD choice alone does not prove a link is malicious; this is only a weak risk signal.`, "Evaluate the complete domain, sender, and message context instead of judging by TLD alone.", "Low");
    if (SUSPICIOUS_LINK_WORDS.test(`${host}${parsed.pathname}${parsed.search}`)) add(index + 1, candidate, "LINK-007", "Phishing or scam-style wording in URL", "High", "The URL contains wording commonly used in credential theft, fake rewards, wallet scams, or urgent account warnings.", "Do not enter passwords, payment details, wallet recovery phrases, or verification codes. Visit the service through its official app or a manually typed address.", "Medium");
    if (/(?:^|&)(?:url|target|redirect|redirect_url|return|returnto|next|continue|dest|destination|goto)=/i.test(parsed.search.slice(1))) add(index + 1, candidate, "LINK-008", "Redirect parameter may hide final destination", "Medium", "The URL includes a parameter commonly used to pass a second destination. The final landing page may differ from the visible domain.", "Inspect the redirect target safely and only trust allowlisted destinations.", "Medium");
    if (candidate.length > 180) add(index + 1, candidate, "LINK-009", "Unusually long URL", "Low", "Very long URLs can hide encoded destinations or tracking data. Length alone is not evidence of abuse.", "Inspect the hostname and query parameters; avoid sharing the link if it contains private tokens.", "Low");
    const labels = host.split(".");
    if (labels.length >= 5) add(index + 1, candidate, "LINK-010", "Unusually deep subdomain chain", "Medium", "The hostname contains many subdomain labels, which can make the registrable domain harder to notice.", "Read the domain from right to left and verify the actual registrable domain before trusting it.", "Medium");
    if (parsed.protocol === "http:") add(index + 1, candidate, "LINK-011", "Unencrypted HTTP link", "Low", "This link uses HTTP rather than HTTPS, so the connection does not provide standard TLS transport protection.", "Prefer the official HTTPS version and do not submit sensitive information over plain HTTP.", "High");
    if (/%(?:2f|5c|40|2e|3a)/i.test(candidate) || /%[0-9a-f]{2}.*%[0-9a-f]{2}.*%[0-9a-f]{2}/i.test(candidate)) add(index + 1, candidate, "LINK-012", "Encoded URL characters may obscure intent", "Low", "The URL contains several encoded delimiters or characters. Encoding is normal on the web but can make the destination harder to inspect.", "Decode and review the URL using a trusted offline tool; do not paste sensitive tokens into public link checkers.", "Low");
  });
  return findings.sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || a.line - b.line);
}

