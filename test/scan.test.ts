import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { scoreFindings } from "../src/checks";
import { normalizeHostname } from "../src/hostname";
import { BlockedTargetError, isBlockedAddress, safeRequest, vetHost } from "../src/net";

describe("scanner address blocklist (SSRF)", () => {
  it.each([
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
    "224.0.0.1", "255.255.255.255", "198.18.0.1", "::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "::ffff:127.0.0.1",
    "::ffff:10.0.0.1", "64:ff9b::a00:1", "2001:db8::1", "not-an-ip",
  ])("blocks %s", (ip) => expect(isBlockedAddress(ip)).toBe(true));

  it.each(["8.8.8.8", "1.1.1.1", "93.184.215.14", "2606:4700:4700::1111", "2a00:1450:4001:80b::200e"])("allows public %s", (ip) =>
    expect(isBlockedAddress(ip)).toBe(false),
  );

  it("refuses a hostname if ANY of its addresses is internal (DNS split tricks)", async () => {
    const resolver = async () => [{ address: "93.184.215.14", family: 4 }, { address: "10.0.0.5", family: 4 }];
    await expect(vetHost("mixed.example.com", resolver)).rejects.toBeInstanceOf(BlockedTargetError);
  });

  it("refuses non-standard ports and raw IP targets", async () => {
    await expect(safeRequest("https://example.com:8443/")).rejects.toBeInstanceOf(BlockedTargetError);
    await expect(safeRequest("http://169.254.169.254/latest/meta-data/")).rejects.toBeInstanceOf(BlockedTargetError);
    await expect(safeRequest("http://[::1]/")).rejects.toBeInstanceOf(BlockedTargetError);
    await expect(safeRequest("file:///etc/passwd")).rejects.toBeInstanceOf(BlockedTargetError);
  });

  it("refuses a hostname that resolves to the cloud metadata address", async () => {
    const resolver = async () => [{ address: "169.254.169.254", family: 4 }];
    await expect(safeRequest("http://metadata.attacker.example/", { resolver })).rejects.toBeInstanceOf(BlockedTargetError);
  });
});

describe("hostname normalization", () => {
  it.each([
    ["Example.COM", "example.com"],
    ["https://www.example.com/some/path?q=1", "www.example.com"],
    ["http://example.com:443", "example.com"],
    ["bücher.de", "xn--bcher-kva.de"],
  ])("%s -> %s", (input, out) => expect(normalizeHostname(input)).toEqual({ ok: true, hostname: out }));

  it.each(["", "localhost", "127.0.0.1", "[::1]", "foo.internal", "printer.local", "x.railway.internal", "kompile.tv", "wall.kompile.tv", "https://u:p@example.com", "example.com:8080", "ftp://example.com", "nodot", "a..b.com"])(
    "rejects %s",
    (input) => expect(normalizeHostname(input).ok).toBe(false),
  );
});

describe("scoring", () => {
  it("grades by severity", () => {
    const f = (severity: "high" | "medium" | "low", status: "fail" | "warn" | "pass") => ({ id: "x", title: "", severity, status, evidence: "", why: "", fix: "" });
    expect(scoreFindings([f("high", "pass")])).toEqual({ score: 100, grade: "A" });
    expect(scoreFindings([f("high", "fail")]).grade).toBe("C");
    expect(scoreFindings([f("high", "fail"), f("high", "fail"), f("medium", "fail")]).grade).toBe("F");
    expect(scoreFindings([f("low", "warn")]).score).toBe(98);
  });
});

/** Two local servers stand in for websites. The test hook lets the scanner reach 127.0.0.1 only here. */
function server(handler: http.RequestListener) {
  const s = http.createServer(handler);
  return {
    s,
    async listen() {
      await new Promise<void>((r) => s.listen(0, "127.0.0.1", () => r()));
      return (s.address() as AddressInfo).port;
    },
  };
}

describe("runScan against local test sites", () => {
  let badPort = 0;
  let goodPort = 0;
  const FAKE_KEY = ["sk", "live", "Zq9X".repeat(7)].join("_");
  const bad = server((req, res) => {
    if (req.url === "/.env") return res.writeHead(200, { "content-type": "text/plain" }).end("DB_PASSWORD=hunter2\nAPI_KEY=sk_live_secret\n");
    if (req.url === "/.git/HEAD") return res.writeHead(200).end("ref: refs/heads/main\n");
    // Built at runtime so the repository secret scan does not flag this fake key.
    if (req.url === "/assets/app.js") return res.writeHead(200, { "content-type": "text/javascript" }).end(`const stripe = "${FAKE_KEY}";`);
    const origin = req.headers.origin;
    res.writeHead(200, {
      "content-type": "text/html",
      server: "Apache/2.4.29 (Ubuntu)",
      "x-powered-by": "PHP/7.2.1",
      "set-cookie": ["PHPSESSID=abc; path=/"],
      ...(origin ? { "access-control-allow-origin": origin, "access-control-allow-credentials": "true" } : {}),
    });
    res.end('<!doctype html><title>Home</title><script src="/assets/app.js"></script>');
  });
  const good = server((req, res) => {
    if (req.url !== "/") return res.writeHead(404, { "content-type": "text/html" }).end("<!doctype html>not found");
    res.writeHead(200, {
      "content-type": "text/html",
      "strict-transport-security": "max-age=31536000; includeSubDomains",
      "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin-when-cross-origin",
      "set-cookie": ["session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"],
    });
    res.end("<!doctype html><title>Home</title>");
  });

  beforeAll(async () => {
    badPort = await bad.listen();
    goodPort = await good.listen();
  });
  afterAll(() => {
    bad.s.close();
    good.s.close();
  });

  it("flags exposed files, CORS with credentials, version leaks, and weak cookies; never echoes file contents", async () => {
    const report = await runScanVia(badPort);
    const byId = Object.fromEntries(report.findings.map((f) => [f.id, f]));
    expect(byId["KS-17"].status).toBe("fail");
    expect(byId["KS-17"].evidence).toContain("Stripe or Clerk secret key");
    expect(byId["KS-17"].evidence).toContain("/assets/app.js");
    expect(JSON.stringify(report)).not.toContain(FAKE_KEY);
    expect(byId["KS-12"].status).toBe("fail");
    expect(byId["KS-12"].evidence).toContain("/.env");
    expect(byId["KS-12"].evidence).toContain("/.git/HEAD");
    expect(JSON.stringify(report)).not.toContain("hunter2");
    expect(JSON.stringify(report)).not.toContain("sk_live_secret");
    expect(byId["KS-13"].status).toBe("fail");
    expect(byId["KS-11"].status).toBe("fail");
    expect(byId["KS-10"].status).toBe("fail");
    expect(byId["KS-05"].status).toBe("fail");
    expect(["D", "F"]).toContain(report.grade);
  });

  it("gives a hardened site a clean result on the same checks", async () => {
    const report = await runScanVia(goodPort);
    const failing = report.findings.filter((f) => f.status === "fail").map((f) => f.id);
    expect(failing).toEqual([]);
    expect(report.grade).toBe("A");
  });

  /** Runs the real checks with every URL rewritten to the local test server. */
  async function runScanVia(port: number) {
    const checks = await import("../src/checks");
    const net = await import("../src/net");
    const real = net.safeRequest;
    const rewrite = (u: string) => {
      const x = new URL(u);
      return `http://scan-target.test:${port}${x.pathname}${x.search}`;
    };
    // Plain HTTP to the "https" page: give the checks a response that looks like it came over https.
    const shim: typeof real = async (u, o) => {
      const r = await real(rewrite(u), { ...o, unsafeAllowAddress: (a) => a === "127.0.0.1" });
      return new URL(u).protocol === "https:"
        ? { ...r, url: u, tls: { authorized: true, authorizationError: null, protocol: "TLSv1.3", validTo: new Date(Date.now() + 60 * 86_400_000).toUTCString(), issuer: "Test CA" } }
        : { ...r, status: 301, headers: { ...r.headers, location: u.replace("http://", "https://") } };
    };
    return checks.runScanWith(shim, "scan-target.test", { dns: { txt: async () => [], mx: async () => [] }, budgetMs: 10_000 });
  }
});
