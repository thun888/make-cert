import { derToPem } from "./pem";
import type { KeyAlgorithmId } from "./types";

export interface KeyProfile {
  label: string;
  family: "rsa" | "ec";
  bits?: number;
  curve?: "P-256" | "P-384";
  hash: "SHA-256" | "SHA-384";
}

export const KEY_PROFILES: Record<KeyAlgorithmId, KeyProfile> = {
  "rsa-2048": { label: "RSA 2048", family: "rsa", bits: 2048, hash: "SHA-256" },
  "rsa-3072": { label: "RSA 3072", family: "rsa", bits: 3072, hash: "SHA-256" },
  "rsa-4096": { label: "RSA 4096", family: "rsa", bits: 4096, hash: "SHA-256" },
  "ec-p256": { label: "ECDSA P-256", family: "ec", curve: "P-256", hash: "SHA-256" },
  "ec-p384": { label: "ECDSA P-384", family: "ec", curve: "P-384", hash: "SHA-384" },
};

export interface KeyBundle {
  keys: CryptoKeyPair;
  profile: KeyProfile;
  signAlgorithm: Algorithm | EcdsaParams;
}

export function generateAlgorithm(profile: KeyProfile) {
  if (profile.family === "rsa") {
    return {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: profile.bits,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: profile.hash,
    };
  }
  return { name: "ECDSA", namedCurve: profile.curve };
}

export function signAlgorithmFor(profile: KeyProfile): Algorithm | EcdsaParams {
  if (profile.family === "ec") {
    return { name: "ECDSA", hash: profile.hash };
  }
  return { name: "RSASSA-PKCS1-v1_5" };
}

export async function generateKeyBundle(algorithm: KeyAlgorithmId): Promise<KeyBundle> {
  const profile = KEY_PROFILES[algorithm];
  const keys = (await crypto.subtle.generateKey(generateAlgorithm(profile), true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  return { keys, profile, signAlgorithm: signAlgorithmFor(profile) };
}

export async function privateKeyToPem(key: CryptoKey): Promise<string> {
  const der = await crypto.subtle.exportKey("pkcs8", key);
  return derToPem(der, "PRIVATE KEY");
}

export async function publicKeyToPem(key: CryptoKey): Promise<string> {
  const der = await crypto.subtle.exportKey("spki", key);
  return derToPem(der, "PUBLIC KEY");
}
