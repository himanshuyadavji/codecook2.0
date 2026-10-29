import { expect, test } from "bun:test";
import { scanSpamLinks } from "../src/lib/spam-link-scanner";

test("flags common suspicious URL patterns without opening the URL", () => {
  const findings = scanSpamLinks([
    "https://bit.ly/verify-account-now",
    "http://192.0.2.10/login-confirm",
    "https://accounts.example.com.security-check.click/claim-free-prize",
    "https://xn--pple-43d.example/login",
    "https://example.com/redirect?next=https%3A%2F%2Funknown.example",
  ].join("\n"));

  expect(findings.some((finding) => finding.rule === "LINK-005")).toBe(true);
  expect(findings.some((finding) => finding.rule === "LINK-004")).toBe(true);
  expect(findings.some((finding) => finding.rule === "LINK-007")).toBe(true);
  expect(findings.some((finding) => finding.rule === "LINK-003")).toBe(true);
  expect(findings.some((finding) => finding.rule === "LINK-008")).toBe(true);
  expect(findings.every((finding) => finding.file === "pasted-links.txt")).toBe(true);
});

test("does not label an ordinary HTTPS URL as spam solely for being a URL", () => {
  expect(scanSpamLinks("https://www.example.com/docs/getting-started")).toEqual([]);
});

test("marks malformed entries for review instead of silently dropping them", () => {
  const findings = scanSpamLinks("http://[broken");
  expect(findings).toHaveLength(1);
  expect(findings[0].rule).toBe("LINK-000");
});
