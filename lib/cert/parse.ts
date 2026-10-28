import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { toHex } from "./pem";

export async function sha256Fingerprint(data: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", data);
  return toHex(digest);
}

const KEY_USAGE_NAMES: Array<[number, string]> = [
  [x509.KeyUsageFlags.digitalSignature, "digitalSignature"],
  [x509.KeyUsageFlags.nonRepudiation, "contentCommitment"],
  [x509.KeyUsageFlags.keyEncipherment, "keyEncipherment"],
  [x509.KeyUsageFlags.dataEncipherment, "dataEncipherment"],
  [x509.KeyUsageFlags.keyAgreement, "keyAgreement"],
  [x509.KeyUsageFlags.keyCertSign, "keyCertSign"],
  [x509.KeyUsageFlags.cRLSign, "cRLSign"],
  [x509.KeyUsageFlags.encipherOnly, "encipherOnly"],
  [x509.KeyUsageFlags.decipherOnly, "decipherOnly"],
];

const EKU_NAMES: Record<string, string> = {
  "1.3.6.1.5.5.7.3.1": "serverAuth",
  "1.3.6.1.5.5.7.3.2": "clientAuth",
  "1.3.6.1.5.5.7.3.3": "codeSigning",
  "1.3.6.1.5.5.7.3.4": "emailProtection",
  "1.3.6.1.5.5.7.3.8": "timeStamping",
  "1.3.6.1.5.5.7.3.9": "ocspSigning",
};

export interface ParsedCertificate {
  subject: string;
  issuer: string;
  serialNumber: string;
  notBefore: Date;
  notAfter: Date;
  daysLeft: number;
  isCa: boolean;
  isSelfSigned: boolean;
  sans: Array<{ type: string; value: string }>;
  keyUsages: string[];
  eku: string[];
  signatureAlgorithm: string;
  signatureHash: string;
  keyDescription: string;
  sha256: string;
  sha1: string;
  subjectKeyId?: string;
}

export async function parseCertificate(pem: string): Promise<ParsedCertificate> {
  const certificate = new x509.X509Certificate(pem);
  const raw = certificate.rawData;

  const basic = certificate.getExtension(x509.BasicConstraintsExtension);
  const ku = certificate.getExtension(x509.KeyUsagesExtension);
  const eku = certificate.getExtension(x509.ExtendedKeyUsageExtension);
  const san = certificate.getExtension(x509.SubjectAlternativeNameExtension);
  const ski = certificate.getExtension(x509.SubjectKeyIdentifierExtension);

  const algorithm = certificate.publicKey.algorithm as EcKeyAlgorithm &
    RsaHashedKeyAlgorithm;
  const keyDescription =
    algorithm.name === "ECDSA"
      ? `ECDSA ${algorithm.namedCurve}`
      : `${algorithm.name} ${(algorithm as RsaHashedKeyAlgorithm).modulusLength ?? ""} bit`;

  const signature = certificate.signatureAlgorithm as { name: string; hash?: { name?: string } };

  const [sha256, sha1] = await Promise.all([
    crypto.subtle.digest("SHA-256", raw),
    crypto.subtle.digest("SHA-1", raw),
  ]);

  return {
    subject: certificate.subject,
    issuer: certificate.issuer,
    serialNumber: certificate.serialNumber,
    notBefore: certificate.notBefore,
    notAfter: certificate.notAfter,
    daysLeft: Math.ceil((certificate.notAfter.getTime() - Date.now()) / 86_400_000),
    isCa: basic?.ca ?? false,
    isSelfSigned: certificate.subject === certificate.issuer,
    sans: san ? (san.names.toJSON() as Array<{ type: string; value: string }>) : [],
    keyUsages: ku
      ? KEY_USAGE_NAMES.filter(([flag]) => (ku.usages & flag) !== 0).map(([, name]) => name)
      : [],
    eku: eku
      ? eku.usages.map((usage) =>
          typeof usage === "string" ? EKU_NAMES[usage] ?? usage : String(usage),
        )
      : [],
    signatureAlgorithm: signature.name,
    signatureHash: signature.hash?.name ?? "",
    keyDescription,
    sha256: toHex(sha256),
    sha1: toHex(sha1),
    subjectKeyId: ski?.keyId,
  };
}

/** 校验子证书是否由给定 CA 证书签发。 */
export async function verifyIssuedBy(leafPem: string, caPem: string): Promise<boolean> {
  const leaf = new x509.X509Certificate(leafPem);
  const ca = new x509.X509Certificate(caPem);
  try {
    return await leaf.verify({ publicKey: ca.publicKey });
  } catch {
    return false;
  }
}
