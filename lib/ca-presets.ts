/**
 * 预设 CA 清单。
 *
 * 这些是从公开证书里还原出来的「弱私钥」CA：P-384 曲线的私钥标量小到只有
 * 3~8 个 bit（d*G 与公钥点直接相等），因此可以逐个试出来。
 * 它们只适合用来演示「密钥强度有多重要」，不要用于任何真实环境。
 *
 * 文件放在 public/presets/ 下，浏览器可通过 /presets/<文件名> 直接取到。
 * 注意：public/ 是公开目录，里面的私钥任何人都能下载。
 */

export type PresetFamily = "DV" | "EV" | "OV";

export interface CaPreset {
  /** 稳定的标识，形如 EM-DV-TLS-CA-G3B */
  id: string;
  /** 显示名，取自证书 CN */
  label: string;
  family: PresetFamily;
  /** O=TLS 是服务器证书，O=CS 是代码签名 */
  usage: "TLS" | "CS";
  /** 签发主体归属 */
  operator: string;
  /** 还原出的私钥标量 d（这些证书的私钥只有几个 bit） */
  scalar: number;
  /** d 的二进制位数 */
  bits: number;
  certUrl: string;
  keyUrl: string;
  /** 证书链上的上级 */
  issuer: string;
}

const preset = (row: Omit<CaPreset, "certUrl" | "keyUrl" | "bits">): CaPreset => ({
  ...row,
  bits: row.scalar.toString(2).length,
  certUrl: `/presets/${row.id}.crt.pem`,
  keyUrl: `/presets/${row.id}.key.pem`,
});

export const CA_PRESETS: CaPreset[] = [
  preset({
    id: "EM-DV-TLS-CA-G3B",
    label: "EM DV TLS CA - G3B",
    family: "DV",
    usage: "TLS",
    operator: "eMudhra BV（NL）",
    scalar: 156,
    issuer: "emSign Root TLS CA - G3",
  }),
  preset({
    id: "EM-DV-TLS-CA-G3C",
    label: "EM DV TLS CA - G3C",
    family: "DV",
    usage: "TLS",
    operator: "eMudhra Inc（US）",
    scalar: 230,
    issuer: "emSign Root TLS CA - G3",
  }),
  preset({
    id: "EM-EV-TLS-CA-G3B",
    label: "EM EV TLS CA - G3B",
    family: "EV",
    usage: "TLS",
    operator: "eMudhra BV（NL）",
    scalar: 115,
    issuer: "emSign Root TLS CA - G3",
  }),
  preset({
    id: "EM-EV-TLS-CA-G3C",
    label: "EM EV TLS CA - G3C",
    family: "EV",
    usage: "TLS",
    operator: "eMudhra Inc（US）",
    scalar: 56,
    issuer: "emSign Root TLS CA - G3",
  }),
  preset({
    id: "EM-OV-CS-CA-G3B",
    label: "EM OV CS CA - G3B",
    family: "OV",
    usage: "CS",
    operator: "eMudhra BV（NL）",
    scalar: 66,
    issuer: "emSign Root CS CA - G3",
  }),
  preset({
    id: "EM-OV-CS-CA-G3C",
    label: "EM OV CS CA - G3C",
    family: "OV",
    usage: "CS",
    operator: "eMudhra Inc（US）",
    scalar: 237,
    issuer: "emSign Root CS CA - G3",
  }),
  preset({
    id: "EM-OV-TLS-CA-G3B",
    label: "EM OV TLS CA - G3B",
    family: "OV",
    usage: "TLS",
    operator: "eMudhra BV（NL）",
    scalar: 155,
    issuer: "emSign Root TLS CA - G3",
  }),
  preset({
    id: "EM-OV-TLS-CA-G3C",
    label: "EM OV TLS CA - G3C",
    family: "OV",
    usage: "TLS",
    operator: "eMudhra Inc（US）",
    scalar: 4,
    issuer: "emSign Root TLS CA - G3",
  }),
];

export const PRESET_FAMILY_LABEL: Record<PresetFamily, string> = {
  DV: "DV 域验证",
  EV: "EV 扩展验证",
  OV: "OV 组织验证",
};

export function groupPresets(): Array<{ family: PresetFamily; items: CaPreset[] }> {
  const order: PresetFamily[] = ["DV", "EV", "OV"];
  return order
    .map((family) => ({ family, items: CA_PRESETS.filter((item) => item.family === family) }))
    .filter((group) => group.items.length > 0);
}

export function findPreset(id: string): CaPreset | undefined {
  return CA_PRESETS.find((item) => item.id === id);
}
