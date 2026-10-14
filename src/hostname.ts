// SPDX-License-Identifier: AGPL-3.0-or-later
import { domainToASCII } from "node:url";
import { isIP } from "node:net";

const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
// Names that only make sense on private networks, and our own domains.
const RESERVED_SUFFIXES = [
  "localhost", "local", "internal", "intranet", "lan", "home", "corp", "test", "example", "invalid", "onion", "arpa",
  "railway.internal", "home.arpa",
];
const OWN_DOMAINS = ["kompile.tv"];

export type HostnameCheck = { ok: true; hostname: string } | { ok: false; message: string };

/** Accepts "example.com", "https://www.example.com/path", or an IDN; returns the normalized ASCII hostname. */
export function normalizeHostname(input: string): HostnameCheck {
  let raw = input.trim().toLowerCase();
  if (!raw) return { ok: false, message: "Enter your website's address, for example example.com." };
  if (raw.length > 300) return { ok: false, message: "That address is too long." };
  if (!/^[a-z][a-z0-9+.-]*:\/\//.test(raw)) raw = `https://${raw}`;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, message: "That does not look like a website address." };
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return { ok: false, message: "Enter a website address (http or https)." };
  if (url.username || url.password) return { ok: false, message: "Remove the username or password from the address." };
  if (url.port && url.port !== "80" && url.port !== "443") return { ok: false, message: "Kompile Scan checks websites on the standard ports only." };
  const host = domainToASCII(url.hostname.replace(/\.$/, ""));
  if (!host || isIP(host.replace(/^\[|\]$/g, ""))) return { ok: false, message: "Enter a domain name, not an IP address." };
  const labels = host.split(".");
  if (labels.length < 2 || !labels.every((l) => LABEL.test(l)) || host.length > 253) {
    return { ok: false, message: "That does not look like a public domain name." };
  }
  if (/^[0-9]+$/.test(labels[labels.length - 1])) return { ok: false, message: "Enter a domain name, not an IP address." };
  if (RESERVED_SUFFIXES.some((s) => host === s || host.endsWith(`.${s}`))) {
    return { ok: false, message: "That name is reserved for private networks. Kompile Scan checks public websites only." };
  }
  if (OWN_DOMAINS.some((s) => host === s || host.endsWith(`.${s}`))) {
    return { ok: false, message: "That is a Kompile domain." };
  }
  return { ok: true, hostname: host };
}
