// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Outbound HTTP for Kompile Scan, built to prevent server-side request forgery.
 *
 * A user who owns a domain could point it at an internal address (our database,
 * a cloud metadata service, a private service on the host network) and use the
 * scanner to read it. So every connection:
 *   - resolves the hostname itself and refuses it if ANY address is private,
 *     loopback, link-local, carrier-grade NAT, multicast, documentation, or
 *     otherwise reserved (IPv4 and IPv6, including IPv4-mapped IPv6),
 *   - connects to the vetted address it resolved (no second lookup, so DNS
 *     rebinding cannot swap the address after the check),
 *   - only uses ports 80 and 443,
 *   - never follows redirects automatically (the caller decides, and every hop
 *     goes through this same check),
 *   - has short timeouts and a hard cap on how much of a body it reads.
 */
import { lookup as dnsLookup } from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import { BlockList, isIP, type LookupFunction } from "node:net";
import type { TLSSocket } from "node:tls";

// Separate lists per family: Node's BlockList matches IPv4 addresses against
// IPv4-mapped IPv6 rules, so one shared list would block every IPv4 address.
const blocked4 = new BlockList();
for (const [net, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) blocked4.addSubnet(net, prefix, "ipv4");
const blocked6 = new BlockList();
for (const [net, prefix] of [
  ["::", 128], ["::1", 128], ["::ffff:0:0", 96], ["64:ff9b::", 96], ["64:ff9b:1::", 48], ["100::", 64], ["2001::", 23],
  ["2001:db8::", 32], ["2002::", 16], ["fc00::", 7], ["fe80::", 10], ["fec0::", 10], ["ff00::", 8],
] as const) blocked6.addSubnet(net, prefix, "ipv6");

/** True when an address must never be contacted by the scanner. */
export function isBlockedAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return blocked4.check(address, "ipv4");
  if (family === 6) {
    // IPv4-mapped (::ffff:a.b.c.d), NAT64 and 6to4 forms are refused outright: they
    // are the classic way to smuggle an internal IPv4 address past an IPv6 check.
    if (/^::ffff:/i.test(address)) return true;
    return blocked6.check(address, "ipv6");
  }
  return true;
}

export class BlockedTargetError extends Error {}

export type Resolver = (hostname: string) => Promise<Array<{ address: string; family: number }>>;
const defaultResolver: Resolver = (h) => dnsLookup(h, { all: true, verbatim: true });

/** Resolves and vets every address. Throws if none, or if any is internal. */
export async function vetHost(hostname: string, resolve: Resolver = defaultResolver): Promise<{ address: string; family: number }> {
  const addrs = await resolve(hostname).catch(() => []);
  if (!addrs.length) throw new BlockedTargetError(`${hostname} does not resolve to any address`);
  const bad = addrs.find((a) => isBlockedAddress(a.address));
  if (bad) throw new BlockedTargetError(`${hostname} resolves to a private or reserved address, which Kompile Scan does not contact`);
  return addrs[0];
}

export interface SafeResponse {
  url: string;
  status: number;
  headers: Record<string, string | string[] | undefined>;
  setCookies: string[];
  body: string;
  bodyTruncated: boolean;
  tls?: { authorized: boolean; authorizationError: string | null; protocol: string | null; validTo: string | null; issuer: string | null };
  remoteAddress: string;
}

export interface SafeRequestOptions {
  method?: "GET" | "HEAD";
  headers?: Record<string, string>;
  timeoutMs?: number;
  maxBodyBytes?: number;
  /** Injected for tests only. Production always uses the vetted system resolver. */
  resolver?: Resolver;
  /** Tests only: allow connecting to a local test server. Never set from configuration. */
  unsafeAllowAddress?: (address: string) => boolean;
}

const USER_AGENT = "KompileScan/1.0 (+https://kompile.tv/scan; owner-verified, read-only)";

export async function safeRequest(rawUrl: string, opts: SafeRequestOptions = {}): Promise<SafeResponse> {
  const url = new URL(rawUrl);
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new BlockedTargetError("only http and https are scanned");
  const port = url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80;
  const allowLocal = opts.unsafeAllowAddress;
  if (!allowLocal && port !== 80 && port !== 443) throw new BlockedTargetError("only ports 80 and 443 are scanned");
  if (isIP(url.hostname.replace(/^\[|\]$/g, ""))) throw new BlockedTargetError("scan targets must be hostnames, not IP addresses");

  const target = allowLocal
    ? { address: "127.0.0.1", family: 4 }
    : await vetHost(url.hostname, opts.resolver);
  if (allowLocal && !allowLocal(target.address)) throw new BlockedTargetError("address not allowed by test hook");

  // Pin the connection to the vetted address: no second DNS lookup can change it.
  const pinned: LookupFunction = (_host, options, cb) => {
    if ((options as { all?: boolean }).all) (cb as unknown as (e: null, a: Array<{ address: string; family: number }>) => void)(null, [target]);
    else cb(null, target.address, target.family);
  };

  const timeoutMs = opts.timeoutMs ?? 8_000;
  const maxBody = opts.maxBodyBytes ?? 256 * 1024;
  const mod = url.protocol === "https:" ? https : http;

  return new Promise<SafeResponse>((resolve, reject) => {
    const req = mod.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port,
        path: `${url.pathname}${url.search}`,
        method: opts.method ?? "GET",
        headers: { "user-agent": USER_AGENT, accept: "*/*", ...opts.headers },
        lookup: pinned,
        timeout: timeoutMs,
        agent: false,
        ...(url.protocol === "https:" ? { servername: url.hostname, rejectUnauthorized: false } : {}),
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        let truncated = false;
        const socket = res.socket as TLSSocket;
        let tls: SafeResponse["tls"];
        if (url.protocol === "https:" && typeof socket.getPeerCertificate === "function") {
          const cert = socket.getPeerCertificate();
          tls = {
            authorized: socket.authorized,
            authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
            protocol: socket.getProtocol?.() ?? null,
            validTo: cert?.valid_to ?? null,
            issuer: cert?.issuer ? [cert.issuer.O, cert.issuer.CN].filter(Boolean).join(" / ") : null,
          };
        }
        res.on("data", (d: Buffer) => {
          if (truncated) return;
          size += d.length;
          if (size > maxBody) {
            truncated = true;
            chunks.push(d.subarray(0, Math.max(0, d.length - (size - maxBody))));
            res.destroy();
            return;
          }
          chunks.push(d);
        });
        const done = () =>
          resolve({
            url: url.toString(),
            status: res.statusCode ?? 0,
            headers: res.headers,
            setCookies: ([] as string[]).concat(res.headers["set-cookie"] ?? []),
            body: Buffer.concat(chunks).toString("utf8"),
            bodyTruncated: truncated,
            tls,
            remoteAddress: target.address,
          });
        res.on("end", done);
        res.on("close", done);
        res.on("error", done);
      },
    );
    const deadline = setTimeout(() => req.destroy(new Error("timed out")), timeoutMs + 1_000);
    req.on("timeout", () => req.destroy(new Error("timed out")));
    req.on("error", (e) => {
      clearTimeout(deadline);
      reject(e);
    });
    req.on("close", () => clearTimeout(deadline));
    req.end();
  });
}
