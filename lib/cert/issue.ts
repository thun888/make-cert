import "reflect-metadata";
import * as asn1js from "asn1js";
import * as x509 from "@peculiar/x509";
import { extractPem, pemToDer, randomSerialNumber, toHex } from "./pem";
import { generateKeyBundle, privateKeyToPem, KEY_PROFILES } from "./keys";
import type { IssueRequest, IssueResult, SubjectInput } from "./types";
import { sha256Fingerprint } from "./parse";

const DN_ESCAPE = /([,=+<>#;"\\])/g;

export function buildDistinguishedName(subject: SubjectInput): string {
  const parts: string[] = [];
  const push = (key: string, value: string) => {
    const trimmed = value.trim();
    if (!trimmed) return;
    parts.push(`${key}=${trimmed.replace(DN_ESCAPE, "\\$1")}`);
  };
  push("CN", subject.commonName);
  push("O", subject.organization);
  push("OU", subject.organizationalUnit);
  push("L", subject.locality);
  push("ST", subject.state);
  push("C", subject.country.toUpperCase());
  push("emailAddress", subject.email);
  return parts.join(", ");
}

export function signAlgorithmForPublicKey(publicKey: CryptoKey): Algorithm | EcdsaParams {
  const algorithm = publicKey.algorithm as EcKeyAlgorithm & RsaHashedKeyAlgorithm;
  if (algorithm.name === "ECDSA") {
    const hash = (algorithm as { hash?: { name?: string } }).hash?.name ?? "SHA-256";
    return { name: "ECDSA", hash };
  }
  return { name: "RSASSA-PKCS1-v1_5" };
}

const CURVE_OIDS: Record<string, string> = {
  "P-256": "1.2.840.10045.3.1.7",
  "P-384": "1.3.132.0.34",
  "P-521": "1.3.132.0.35",
};

/** 把 OpenSSL 的 PKCS#1 / SEC1 私钥包装成 WebCrypto 需要的 PKCS#8。 */
function legacyPrivateKeyToPkcs8(der: Uint8Array, namedCurve?: string): Uint8Array {
  const isEc = Boolean(namedCurve);
  const algorithmIdentifier = isEc
    ? new asn1js.Sequence({
        value: [
          new asn1js.ObjectIdentifier({ value: "1.2.840.10045.2.1" }),
          new asn1js.ObjectIdentifier({ value: CURVE_OIDS[namedCurve as string] ?? CURVE_OIDS["P-256"] }),
        ],
      })
    : new asn1js.Sequence({
        value: [
          new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.1.1" }),
          new asn1js.Null(),
        ],
      });

  const keyBytes = der.slice().buffer;
  const sequence = new asn1js.Sequence({
    value: [
      new asn1js.Integer({ value: 0 }),
      algorithmIdentifier,
      new asn1js.OctetString({ valueHex: keyBytes }),
    ],
  });
  return new Uint8Array(sequence.toBER(false));
}

export async function importCaPrivateKey(
  keyText: string,
  caCertificate: x509.X509Certificate,
): Promise<CryptoKey> {
  const pkcs8 = extractPem(keyText, "PRIVATE KEY");
  const pkcs1 = extractPem(keyText, "RSA PRIVATE KEY");
  const sec1 = extractPem(keyText, "EC PRIVATE KEY");

  const algorithm = caCertificate.publicKey.algorithm as EcKeyAlgorithm & RsaHashedKeyAlgorithm;
  const isEc = algorithm.name === "ECDSA";

  let der: Uint8Array;
  if (pkcs8) {
    der = pemToDer(pkcs8);
  } else if (pkcs1) {
    der = legacyPrivateKeyToPkcs8(pemToDer(pkcs1));
  } else if (sec1) {
    der = legacyPrivateKeyToPkcs8(pemToDer(sec1), algorithm.namedCurve);
  } else {
    throw new Error("未找到可用的 CA 私钥：需要 PEM 格式的 PRIVATE KEY / RSA PRIVATE KEY / EC PRIVATE KEY。");
  }

  const importAlgorithm = isEc
    ? { name: "ECDSA", namedCurve: algorithm.namedCurve }
    : {
        name: "RSASSA-PKCS1-v1_5",
        hash:
          typeof (algorithm as unknown as { hash?: unknown }).hash === "object"
            ? ((algorithm as unknown as { hash: { name?: string } }).hash.name ?? "SHA-256")
            : ((algorithm as unknown as { hash?: string }).hash ?? "SHA-256"),
      };

  try {
    return await crypto.subtle.importKey(
      "pkcs8",
      der as unknown as BufferSource,
      importAlgorithm,
      false,
      ["sign"],
    );
  } catch {
    throw new Error("CA 私钥与 CA 证书的算法不匹配，或私钥已加密（请提供未加密的私钥）。");
  }
}

/** 优先用 CA 证书自带的 SKI 生成 AKI，缺失时回退到公钥哈希。 */
async function authorityKeyIdFor(
  caCertificate: x509.X509Certificate,
): Promise<x509.AuthorityKeyIdentifierExtension | null> {
  const ski = caCertificate.getExtension(x509.SubjectKeyIdentifierExtension);
  if (ski) {
    return new x509.AuthorityKeyIdentifierExtension(ski.keyId);
  }
  try {
    const spki = await crypto.subtle.exportKey(
      "spki",
      caCertificate.publicKey as unknown as CryptoKey,
    );
    const digest = await crypto.subtle.digest("SHA-1", spki);
    return new x509.AuthorityKeyIdentifierExtension(toHex(digest, ""));
  } catch {
    return null;
  }
}

export async function issueCertificate(request: IssueRequest): Promise<IssueResult> {
  const profile = KEY_PROFILES[request.algorithm];
  const { keys, signAlgorithm } = await generateKeyBundle(request.algorithm);

  const notBefore = new Date(Date.now() - 5 * 60 * 1000);
  const notAfter = new Date(notBefore.getTime() + request.days * 24 * 60 * 60 * 1000);
  const serialNumber = randomSerialNumber(16);
  const name = buildDistinguishedName(request.subject);

  const isCa = request.mode === "ca";
  const isEc = profile.family === "ec";

  const keyUsages = isCa
    ? x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign
    : x509.KeyUsageFlags.digitalSignature | (isEc ? 0 : x509.KeyUsageFlags.keyEncipherment);

  const extensions: x509.Extension[] = [
    new x509.BasicConstraintsExtension(isCa, isCa ? request.pathLength : undefined, true),
    new x509.KeyUsagesExtension(keyUsages, true),
  ];

  if (!isCa) {
    const usages = [x509.ExtendedKeyUsage.serverAuth];
    if (request.includeClientAuth) usages.push(x509.ExtendedKeyUsage.clientAuth);
    extensions.push(new x509.ExtendedKeyUsageExtension(usages, false));
  }

  const sanEntries = request.sans
    .map((entry) => ({ type: entry.type, value: entry.value.trim() }))
    .filter((entry) => entry.value.length > 0);

  if (!isCa && sanEntries.length > 0) {
    extensions.push(
      new x509.SubjectAlternativeNameExtension(
        sanEntries.map((entry) => ({ type: entry.type, value: entry.value })),
        false,
      ),
    );
  }

  extensions.push(await x509.SubjectKeyIdentifierExtension.create(keys.publicKey));

  let certificate: x509.X509Certificate;
  const chain: string[] = [];

  if (request.mode === "leaf") {
    if (!request.caCertPem || !request.caKeyPem) {
      throw new Error("请先填入 CA 证书与 CA 私钥。");
    }
    const caCertificate = new x509.X509Certificate(extractPem(request.caCertPem, "CERTIFICATE") ?? request.caCertPem);
    const caKey = await importCaPrivateKey(request.caKeyPem, caCertificate);

    const aki = await authorityKeyIdFor(caCertificate);
    if (aki) extensions.push(aki);

    certificate = await x509.X509CertificateGenerator.create({
      serialNumber,
      subject: name,
      issuer: caCertificate.subject,
      notBefore,
      notAfter,
      signingAlgorithm: signAlgorithmForPublicKey(caCertificate.publicKey as unknown as CryptoKey),
      publicKey: keys.publicKey,
      signingKey: caKey,
      extensions,
    });
    chain.push(caCertificate.toString("pem"));
  } else {
    certificate = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber,
      name,
      notBefore,
      notAfter,
      signingAlgorithm: signAlgorithm,
      keys,
      extensions,
    });
  }

  const certPem = certificate.toString("pem");
  const keyPem = await privateKeyToPem(keys.privateKey);

  let csrPem: string | undefined;
  if (request.includeCsr) {
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
      name,
      keys,
      signingAlgorithm: signAlgorithm,
      extensions:
        sanEntries.length > 0
          ? [
              new x509.SubjectAlternativeNameExtension(
                sanEntries.map((entry) => ({ type: entry.type, value: entry.value })),
                false,
              ),
            ]
          : [],
    });
    csrPem = csr.toString("pem");
  }

  return {
    mode: request.mode,
    subject: certificate.subject,
    serialNumber: certificate.serialNumber,
    notBefore: certificate.notBefore,
    notAfter: certificate.notAfter,
    certPem,
    keyPem,
    chainPem: chain.join("\n"),
    fullchainPem: [certPem, ...chain].join("\n"),
    csrPem,
    sha256: await sha256Fingerprint(certificate.rawData),
    keyLabel: profile.label,
  };
}
