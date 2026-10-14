import { describe, expect, it } from "vitest";
import { ctSubdomains, HIJACKED_CDNS, PANELS, SECRET_KEY_PATTERNS, TAKEOVER_PROVIDERS, versionBelow, VULN_LIBS, type Requester } from "../src/checks";

const k = (...parts: string[]) => parts.join("");

describe("checks added from the 10/12 tool research", () => {
  it("compares versions numerically", () => {
    expect(versionBelow("3.4.1", "3.5.0")).toBe(true);
    expect(versionBelow("3.10.0", "3.5.0")).toBe(false);
    expect(versionBelow("15.2.3", "15.2.3")).toBe(false);
  });

  it("flags hijacked CDNs and not their safe replacements", () => {
    expect(HIJACKED_CDNS.test("polyfill.io")).toBe(true);
    expect(HIJACKED_CDNS.test("cdn.polyfill.io")).toBe(true);
    expect(HIJACKED_CDNS.test("cdnjs.cloudflare.com")).toBe(false);
    expect(HIJACKED_CDNS.test("notpolyfill.io.example.com")).toBe(false);
  });

  it("reads library versions from CDN links and banners", () => {
    const jq = VULN_LIBS.find((l) => l.name === "jQuery")!;
    const v = jq.re.exec('<script src="https://code.jquery.com/jquery-3.4.1.min.js">')!.slice(1).find(Boolean);
    expect(v).toBe("3.4.1");
    const lodash = VULN_LIBS.find((l) => l.name === "Lodash")!;
    expect(lodash.re.exec("https://cdn.jsdelivr.net/npm/lodash@4.17.15/lodash.min.js")!.slice(1).find(Boolean)).toBe("4.17.15");
  });

  it("matches new secret key formats but never publishable keys", () => {
    const hit = (s: string) => SECRET_KEY_PATTERNS.some(([, re]) => re.test(s));
    expect(hit(k("gsk", "_", "Ab3d".repeat(13)))).toBe(true);
    expect(hit(k("sk-or-v1-", "a1".repeat(32)))).toBe(true);
    expect(hit(k("hooks.slack.com/services/", "T0000/B0000/", "x".repeat(24)))).toBe(true);
    expect(hit(k("pk", "_live_", "Y2xlcmsuZXhhbXBsZS5jb20k"))).toBe(false);
    expect(hit(k("pk.", "eyJ1Ijoia29tcGlsZSJ9", ".abc"))).toBe(false);
  });

  it("recognises unclaimed-provider pages and ignores live ones", () => {
    const gh = TAKEOVER_PROVIDERS.find((p) => p.name === "GitHub Pages")!;
    expect(gh.cname.test("someone.github.io")).toBe(true);
    expect(gh.body!.test("<h1>404</h1><p>There isn't a GitHub Pages site here.</p>")).toBe(true);
    expect(gh.body!.test("<h1>Welcome to my docs</h1>")).toBe(false);
    const s3 = TAKEOVER_PROVIDERS.find((p) => p.name === "AWS S3")!;
    expect(s3.cname.test("assets.s3.amazonaws.com")).toBe(true);
    expect(s3.body!.test("<Code>NoSuchBucket</Code>")).toBe(true);
  });

  it("keeps only real subdomains of the scanned host from certificate logs", async () => {
    const fake: Requester = async () =>
      ({
        status: 200,
        headers: {},
        setCookies: [],
        url: "https://crt.sh/",
        body: JSON.stringify([
          { name_value: "app.example.com\nwww.app.example.com" },
          { name_value: "*.app.example.com" },
          { name_value: "old.app.example.com" },
          { name_value: "evil-app.example.com.attacker.net" },
          { name_value: "app.example.com" },
        ]),
      }) as never;
    expect(await ctSubdomains(fake, "app.example.com", {})).toEqual(["old.app.example.com", "www.app.example.com"]);
  });

  it("matches panels by fingerprint only", () => {
    const ollama = PANELS.find((p) => p.label.startsWith("an Ollama"))!;
    expect(ollama.re.test('{"models":[{"name":"llama3"}]}')).toBe(true);
    expect(ollama.re.test('{"tags":["news"]}')).toBe(false);
  });
});
