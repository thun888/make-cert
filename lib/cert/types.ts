export type KeyAlgorithmId =
  | "rsa-2048"
  | "rsa-3072"
  | "rsa-4096"
  | "ec-p256"
  | "ec-p384";

export type IssueMode = "self" | "ca" | "leaf";

export type SanType = "dns" | "ip" | "email" | "url";

export interface SanEntry {
  id: string;
  type: SanType;
  value: string;
}

export interface SubjectInput {
  commonName: string;
  organization: string;
  organizationalUnit: string;
  country: string;
  state: string;
  locality: string;
  email: string;
}

export interface IssueRequest {
  mode: IssueMode;
  subject: SubjectInput;
  sans: SanEntry[];
  algorithm: KeyAlgorithmId;
  days: number;
  pathLength: number;
  includeClientAuth: boolean;
  includeCsr: boolean;
  caCertPem?: string;
  caKeyPem?: string;
}

export interface IssueResult {
  mode: IssueMode;
  subject: string;
  serialNumber: string;
  notBefore: Date;
  notAfter: Date;
  certPem: string;
  keyPem: string;
  chainPem: string;
  fullchainPem: string;
  csrPem?: string;
  sha256: string;
  keyLabel: string;
}

export interface CheckItem {
  level: "error" | "warn" | "info";
  title: string;
  detail?: string;
}
