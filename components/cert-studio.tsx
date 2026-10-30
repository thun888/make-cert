"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { issueCertificate } from "@/lib/cert/issue";
import { defaultSans, isIpAddress, validateRequest, validateSanEntry } from "@/lib/cert/validate";
import type {
  CheckItem,
  IssueMode,
  IssueRequest,
  IssueResult,
  KeyAlgorithmId,
  SanEntry,
  SubjectInput,
} from "@/lib/cert/types";
import { sanitizeBaseName } from "@/lib/download";
import { deleteCa, listCas, saveCa, type StoredCa } from "@/lib/ca-store";
import { describeCaBundle, readPkcs12, splitPemMaterials, type CaBundle } from "@/lib/cert/import";
import { formatDate } from "@/lib/cert/pem";
import { CA_PRESETS, PRESET_FAMILY_LABEL, findPreset, groupPresets } from "@/lib/ca-presets";
import { Button, Card, CardHeader, Field, Segmented, Select, TextInput, Textarea } from "./ui";
import { ResultPanel } from "./result-panel";
import { Inspector } from "./inspector";

const MODE_HINTS: Record<IssueMode, string> = {
  self: "生成一张自签名证书，用于本地开发或测试服务器。",
  leaf: "用已有的 CA 为站点签发证书，需要 CA 证书与对应的私钥。",
  ca: "生成一个自建根 CA，用于签发内网或测试环境的证书。",
};

const ALGORITHMS: Array<{ value: KeyAlgorithmId; label: string }> = [
  { value: "rsa-2048", label: "RSA 2048（兼容性最好）" },
  { value: "rsa-3072", label: "RSA 3072" },
  { value: "rsa-4096", label: "RSA 4096（生成较慢）" },
  { value: "ec-p256", label: "ECDSA P-256（体积小、握手快）" },
  { value: "ec-p384", label: "ECDSA P-384" },
];

const EMPTY_SUBJECT: SubjectInput = {
  commonName: "localhost",
  organization: "",
  organizationalUnit: "",
  country: "",
  state: "",
  locality: "",
  email: "",
};

const LEVEL_STYLES: Record<CheckItem["level"], { dot: string; text: string; label: string }> = {
  error: { dot: "bg-rose-500", text: "text-rose-700", label: "必须处理" },
  warn: { dot: "bg-amber-500", text: "text-amber-700", label: "建议注意" },
  info: { dot: "bg-zinc-300", text: "text-zinc-600", label: "提示" },
};

// 渲染期不调用 Date.now()（React 纯函数约束），用页面加载时刻做「是否已过期」的粗判断
const PAGE_LOADED_AT = Date.now();

export function CertStudio() {
  const [mode, setMode] = useState<IssueMode>("self");
  const [subject, setSubject] = useState<SubjectInput>(EMPTY_SUBJECT);
  const [sans, setSans] = useState<SanEntry[]>(defaultSans("localhost"));
  const [algorithm, setAlgorithm] = useState<KeyAlgorithmId>("rsa-2048");
  const [days, setDays] = useState(397);
  const [pathLength, setPathLength] = useState(0);
  const [includeClientAuth, setIncludeClientAuth] = useState(false);
  const [includeCsr, setIncludeCsr] = useState(false);
  const [caCertPem, setCaCertPem] = useState("");
  const [caKeyPem, setCaKeyPem] = useState("");

  const [result, setResult] = useState<IssueResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [savedCas, setSavedCas] = useState<StoredCa[]>([]);
  const [selectedCaId, setSelectedCaId] = useState("");
  const [imported, setImported] = useState<CaBundle | null>(null);
  const [importNote, setImportNote] = useState<{ tone: "ok" | "err"; text: string } | null>(null);
  const [importing, setImporting] = useState(false);
  const [importDragging, setImportDragging] = useState(false);
  const [pendingPkcs12, setPendingPkcs12] = useState<Uint8Array | null>(null);
  const [p12Password, setP12Password] = useState("");
  const [presetId, setPresetId] = useState("");
  const [presetBusy, setPresetBusy] = useState(false);
  const importFileRef = useRef<HTMLInputElement>(null);

  const activePreset = useMemo(() => findPreset(presetId), [presetId]);
  const presetGroups = useMemo(() => groupPresets(), []);

  const applyBundle = (bundle: CaBundle) => {
    setImported(bundle);
    if (bundle.certPem) setCaCertPem(bundle.certPem);
    if (bundle.keyPem) setCaKeyPem(bundle.keyPem);

    if (!bundle.certPem) {
      setImportNote({ tone: "err", text: bundle.notes[0] ?? "没有找到证书。" });
      return;
    }
    if (!bundle.keyPem) {
      setImportNote({ tone: "err", text: "只找到证书，没有私钥——签发叶子证书还需要对应的私钥文件。" });
      return;
    }
    if (bundle.keyMatchesCert === false) {
      setImportNote({ tone: "err", text: "私钥与证书不配对，这样签出来的证书链会校验失败。" });
      return;
    }
    setImportNote({
      tone: "ok",
      text: `已导入 ${bundle.subject ?? "证书"}${bundle.isCa ? "" : "（注意：这不是 CA 证书）"}`,
    });
  };

  const handleImportFile = async (file: File) => {
    setImportNote(null);
    setImported(null);
    setPendingPkcs12(null);
    setPresetId("");
    setImporting(true);
    try {
      const name = file.name.toLowerCase();
      if (name.endsWith(".p12") || name.endsWith(".pfx")) {
        setPendingPkcs12(new Uint8Array(await file.arrayBuffer()));
        setImportNote({ tone: "ok", text: "文件受口令保护，请输入口令后解锁。" });
        return;
      }
      const text = await file.text();
      const materials = splitPemMaterials(text);
      // 证书和私钥经常分成两个文件下载，缺哪一半就沿用已经填好的内容
      const merged = [
        text,
        materials.certPems.length === 0 ? caCertPem : "",
        materials.keyPem ? "" : caKeyPem,
      ]
        .filter(Boolean)
        .join("\n");
      applyBundle(await describeCaBundle(merged));
    } catch (cause) {
      setImportNote({ tone: "err", text: cause instanceof Error ? cause.message : "读取失败" });
    } finally {
      setImporting(false);
    }
  };

  const unlockPkcs12 = async () => {
    if (!pendingPkcs12) return;
    setImporting(true);
    setImportNote(null);
    try {
      const { certPems, keyPem } = await readPkcs12(pendingPkcs12, p12Password);
      if (certPems.length === 0) {
        throw new Error("这个 PKCS#12 文件里没有证书。");
      }
      applyBundle(await describeCaBundle(certPems.join("\n"), keyPem));
      setPendingPkcs12(null);
      setP12Password("");
    } catch (cause) {
      setImportNote({ tone: "err", text: cause instanceof Error ? cause.message : "解锁失败" });
    } finally {
      setImporting(false);
    }
  };

  const loadPresetCa = async (id: string) => {
    setPresetId(id);
    const preset = findPreset(id);
    if (!preset) return;

    setImportNote(null);
    setImported(null);
    setPendingPkcs12(null);
    setSelectedCaId("");
    setPresetBusy(true);
    try {
      const [certResponse, keyResponse] = await Promise.all([fetch(preset.certUrl), fetch(preset.keyUrl)]);
      if (!certResponse.ok || !keyResponse.ok) {
        throw new Error(
          `预设文件读取失败（证书 HTTP ${certResponse.status}，私钥 HTTP ${keyResponse.status}）`,
        );
      }
      const certPem = await certResponse.text();
      const keyPem = await keyResponse.text();
      applyBundle(await describeCaBundle(certPem, keyPem));
    } catch (cause) {
      setImportNote({ tone: "err", text: cause instanceof Error ? cause.message : "载入预设 CA 失败" });
    } finally {
      setPresetBusy(false);
    }
  };

  const clearPresetCa = () => {
    setPresetId("");
    setImported(null);
    setImportNote(null);
    setCaCertPem("");
    setCaKeyPem("");
  };

  const saveImportedCa = async () => {
    if (!imported?.certPem || !imported.keyPem || !imported.sha256) return;
    await saveCa({
      id: imported.sha256,
      name: imported.subject ?? "导入的 CA",
      certPem: imported.certPem,
      keyPem: imported.keyPem,
      createdAt: Date.now(),
      notAfter: imported.notAfter?.getTime() ?? 0,
    });
    setSavedCas(await listCas());
    setImportNote({ tone: "ok", text: "已存入本地 CA 库，下次可直接选用。" });
  };

  useEffect(() => {
    if (mode !== "leaf") return;
    let active = true;
    listCas()
      .then((items) => {
        if (active) setSavedCas(items);
      })
      .catch(() => {
        if (active) setSavedCas([]);
      });
    return () => {
      active = false;
    };
  }, [mode]);

  const applySavedCa = (id: string) => {
    setSelectedCaId(id);
    setPresetId("");
    const ca = savedCas.find((item) => item.id === id);
    if (!ca) return;
    setCaCertPem(ca.certPem);
    setCaKeyPem(ca.keyPem);
  };

  const removeSavedCa = async () => {
    if (!selectedCaId) return;
    await deleteCa(selectedCaId);
    setSavedCas((prev) => prev.filter((item) => item.id !== selectedCaId));
    setSelectedCaId("");
    setPresetId("");
    setCaCertPem("");
    setCaKeyPem("");
  };

  const request = useMemo<IssueRequest>(
    () => ({
      mode,
      subject,
      sans,
      algorithm,
      days,
      pathLength,
      includeClientAuth,
      includeCsr,
      caCertPem,
      caKeyPem,
    }),
    [mode, subject, sans, algorithm, days, pathLength, includeClientAuth, includeCsr, caCertPem, caKeyPem],
  );

  const checks = useMemo(() => validateRequest(request), [request]);
  const hasError = checks.some((item) => item.level === "error");

  const baseName = useMemo(() => {
    const primary = sans.find((entry) => entry.type === "dns" && entry.value.trim());
    return sanitizeBaseName(primary?.value || subject.commonName || "certificate");
  }, [sans, subject.commonName]);

  const switchMode = (next: IssueMode) => {
    setMode(next);
    setDays(next === "ca" ? 3650 : 397);
    setError(null);
    // CA 不需要 SAN，顺手把默认的 localhost 换成可识别的名称
    setSubject((prev) => {
      if (next === "ca" && prev.commonName.trim() === "localhost") {
        return { ...prev, commonName: "Local Root CA" };
      }
      if (next !== "ca" && prev.commonName.trim() === "Local Root CA") {
        return { ...prev, commonName: "localhost" };
      }
      return prev;
    });
  };

  const updateCommonName = (value: string) => {
    setSubject((prev) => ({ ...prev, commonName: value }));
    setSans((prev) =>
      prev.length === 1 && prev[0].id === "san-primary"
        ? [{ ...prev[0], type: isIpAddress(value.trim()) ? "ip" : "dns", value }]
        : prev,
    );
  };

  const updateSan = (id: string, patch: Partial<SanEntry>) => {
    setSans((prev) => prev.map((entry) => (entry.id === id ? { ...entry, ...patch } : entry)));
  };

  const addSan = (type: SanEntry["type"] = "dns", value = "") => {
    setSans((prev) => [...prev, { id: crypto.randomUUID(), type, value }]);
  };

  const generate = async () => {
    setBusy(true);
    setError(null);
    try {
      const issued = await issueCertificate(request);
      setResult(issued);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "生成失败，请检查输入。");
    } finally {
      setBusy(false);
    }
  };

  const useAsCa = (certPem: string, keyPem: string) => {
    setCaCertPem(certPem);
    setCaKeyPem(keyPem);
    switchMode("leaf");
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-[minmax(0,540px)_minmax(0,1fr)]">
        <Card className="min-w-0 overflow-hidden">
          <CardHeader title="证书参数" description="填写主体、密钥与有效期。" />

          <div className="space-y-5 px-4 py-4 sm:px-5">
            <div className="space-y-2">
              <Segmented
                value={mode}
                onChange={switchMode}
                options={[
                  { value: "self", label: "自签名" },
                  { value: "leaf", label: "用 CA 签发" },
                  { value: "ca", label: "生成根 CA" },
                ]}
              />
              <p className="text-[11px] leading-relaxed text-zinc-500">{MODE_HINTS[mode]}</p>
            </div>

            <section className="space-y-3">
              <h3 className="text-xs font-medium text-zinc-900">主题信息</h3>
              <div className="grid grid-cols-2 gap-3">
                <Field label="通用名称 CN" className="col-span-2" hint="仅用于显示与旧客户端兼容，浏览器实际只校验 SAN。">
                  <TextInput
                    value={subject.commonName}
                    placeholder="localhost"
                    onChange={(event) => updateCommonName(event.target.value)}
                  />
                </Field>
                <Field label="组织 O">
                  <TextInput
                    value={subject.organization}
                    placeholder="选填，如 Acme Ltd."
                    onChange={(event) => setSubject((prev) => ({ ...prev, organization: event.target.value }))}
                  />
                </Field>
                <Field label="部门 OU">
                  <TextInput
                    value={subject.organizationalUnit}
                    placeholder="选填"
                    onChange={(event) =>
                      setSubject((prev) => ({ ...prev, organizationalUnit: event.target.value }))
                    }
                  />
                </Field>
                <Field label="国家 C">
                  <TextInput
                    value={subject.country}
                    placeholder="CN"
                    maxLength={2}
                    onChange={(event) => setSubject((prev) => ({ ...prev, country: event.target.value }))}
                  />
                </Field>
                <Field label="省 / 州 ST">
                  <TextInput
                    value={subject.state}
                    placeholder="选填"
                    onChange={(event) => setSubject((prev) => ({ ...prev, state: event.target.value }))}
                  />
                </Field>
              </div>
            </section>

            {mode !== "ca" ? (
            <section className="space-y-2 border-t border-zinc-100 pt-4">
              <div className="flex items-baseline justify-between">
                <h3 className="text-xs font-medium text-zinc-900">SAN（主题备用名称）</h3>
                <span className="text-[11px] text-zinc-400">浏览器真正校验的字段</span>
              </div>

              <div className="space-y-2">
                {sans.map((entry) => {
                  const entryError = entry.value.trim() ? validateSanEntry(entry) : null;
                  return (
                    <div key={entry.id} className="space-y-1">
                      <div className="flex gap-2">
                        <div className="w-[92px] shrink-0">
                          <Select
                            value={entry.type}
                            onChange={(event) => updateSan(entry.id, { type: event.target.value as SanEntry["type"] })}
                          >
                            <option value="dns">DNS</option>
                            <option value="ip">IP</option>
                            <option value="email">邮箱</option>
                            <option value="url">URI</option>
                          </Select>
                        </div>
                        <TextInput
                          value={entry.value}
                          placeholder={entry.type === "ip" ? "127.0.0.1" : "example.com 或 *.example.com"}
                          className={`min-w-0 flex-1 ${entryError ? "border-rose-300 focus:border-rose-400" : ""}`}
                          onChange={(event) => updateSan(entry.id, { value: event.target.value })}
                        />
                        <Button
                          variant="ghost"
                          className="shrink-0 px-2"
                          aria-label="删除该条目"
                          onClick={() => setSans((prev) => prev.filter((item) => item.id !== entry.id))}
                        >
                          ✕
                        </Button>
                      </div>
                      {entryError ? <p className="text-[11px] text-rose-600">{entryError}</p> : null}
                    </div>
                  );
                })}
              </div>

              <div className="flex flex-wrap items-center gap-1.5 pt-1">
                <Button variant="secondary" className="px-2 py-1 text-xs" onClick={() => addSan()}>
                  + 添加条目
                </Button>
                {[
                  { label: "localhost", type: "dns" as const },
                  { label: "127.0.0.1", type: "ip" as const },
                  { label: "*.local", type: "dns" as const },
                  { label: "*.demo.test", type: "dns" as const },
                ].map((preset) => (
                  <button
                    key={preset.label}
                    type="button"
                    onClick={() => addSan(preset.type, preset.label)}
                    className="rounded-md bg-zinc-100 px-2 py-1 font-mono text-[11px] text-zinc-600 transition hover:bg-zinc-200"
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
            </section>
            ) : null}

            <section className="grid grid-cols-2 gap-3 border-t border-zinc-100 pt-4">
              <Field label="密钥算法">
                <Select value={algorithm} onChange={(event) => setAlgorithm(event.target.value as KeyAlgorithmId)}>
                  {ALGORITHMS.map((item) => (
                    <option key={item.value} value={item.value}>
                      {item.label}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="有效期（天）" hint={mode === "ca" ? "根 CA 可以长一些" : "建议 ≤ 397"}>
                <TextInput
                  type="number"
                  min={1}
                  max={36500}
                  value={days}
                  onChange={(event) => setDays(Number(event.target.value))}
                />
              </Field>

              {mode === "ca" ? (
                <Field label="pathLen" className="col-span-1" hint="还能再往下签几层中间 CA，0 表示只能签终端证书。">
                  <TextInput
                    type="number"
                    min={0}
                    max={5}
                    value={pathLength}
                    onChange={(event) => setPathLength(Number(event.target.value))}
                  />
                </Field>
              ) : null}

              <div className="col-span-2 flex flex-wrap gap-4 pt-1">
                {mode !== "ca" ? (
                  <label className="flex items-center gap-2 text-xs text-zinc-600">
                    <input
                      type="checkbox"
                      checked={includeClientAuth}
                      onChange={(event) => setIncludeClientAuth(event.target.checked)}
                      className="h-3.5 w-3.5 rounded border-zinc-300 accent-zinc-900"
                    />
                    同时用于客户端认证（clientAuth）
                  </label>
                ) : null}
                <label className="flex items-center gap-2 text-xs text-zinc-600">
                  <input
                    type="checkbox"
                    checked={includeCsr}
                    onChange={(event) => setIncludeCsr(event.target.checked)}
                    className="h-3.5 w-3.5 rounded border-zinc-300 accent-zinc-900"
                  />
                  同时生成 CSR
                </label>
              </div>
            </section>

            {mode === "leaf" ? (
              <section className="space-y-2 border-t border-zinc-100 pt-4">
                <div className="flex items-baseline justify-between">
                  <h3 className="text-xs font-medium text-zinc-900">签发用的 CA</h3>
                  <span className="text-[11px] text-zinc-400">预设 · 本地库 · 文件</span>
                </div>

                <div className="space-y-1.5">
                  <div className="flex gap-2">
                    <Select
                      value={presetId}
                      disabled={presetBusy}
                      onChange={(event) => void loadPresetCa(event.target.value)}
                    >
                      <option value="">{presetBusy ? "正在载入预设…" : "从预设 CA 载入…"}</option>
                      {presetGroups.map((group) => (
                        <optgroup key={group.family} label={PRESET_FAMILY_LABEL[group.family]}>
                          {group.items.map((item) => (
                            <option key={item.id} value={item.id}>
                              {item.label}（{item.usage}）· {item.operator}
                            </option>
                          ))}
                        </optgroup>
                      ))}
                    </Select>
                    {activePreset ? (
                      <Button variant="ghost" className="shrink-0 px-2" aria-label="清除预设" onClick={clearPresetCa}>
                        ✕
                      </Button>
                    ) : null}
                  </div>

                  {activePreset ? (
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="inline-flex items-center rounded-md bg-zinc-100 px-1.5 py-0.5 font-mono text-[11px] text-zinc-600">
                        {PRESET_FAMILY_LABEL[activePreset.family]}
                      </span>
                      <span className="inline-flex items-center rounded-md bg-zinc-100 px-1.5 py-0.5 font-mono text-[11px] text-zinc-600">
                        {activePreset.usage === "CS" ? "代码签名" : "服务器证书"}
                      </span>
                      <span className="inline-flex items-center rounded-md bg-rose-50 px-1.5 py-0.5 font-mono text-[11px] text-rose-700">
                        d = {activePreset.scalar} · {activePreset.bits} bit
                      </span>
                      <span className="text-[11px] text-zinc-400">上级 {activePreset.issuer}</span>
                    </div>
                  ) : (
                    <p className="text-[11px] leading-relaxed text-zinc-400">
                      预设来自 {CA_PRESETS.length} 张真实公开证书，其私钥已从公钥反推得到——标量只有 3~8 bit，
                      因此只能用来演示。
                    </p>
                  )}
                </div>

                <input
                  ref={importFileRef}
                  type="file"
                  accept=".crt,.pem,.cer,.cert,.key,.pfx,.p12"
                  className="hidden"
                  onChange={(event) => {
                    const file = event.target.files?.[0];
                    if (file) void handleImportFile(file);
                    event.target.value = "";
                  }}
                />

                <div
                  className={`rounded-xl border border-dashed px-3 py-2.5 transition ${
                    importDragging ? "border-zinc-400 bg-zinc-50" : "border-zinc-200 bg-zinc-50/50"
                  }`}
                  onDragOver={(event) => {
                    event.preventDefault();
                    setImportDragging(true);
                  }}
                  onDragLeave={() => setImportDragging(false)}
                  onDrop={(event) => {
                    event.preventDefault();
                    setImportDragging(false);
                    const file = event.dataTransfer.files?.[0];
                    if (file) void handleImportFile(file);
                  }}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="min-w-0">
                      <p className="text-xs font-medium text-zinc-700">从本地文件导入</p>
                      <p className="mt-0.5 text-[11px] leading-relaxed text-zinc-400">
                        拖入或选择 .crt / .pem / .key，以及带口令的 .pfx / .p12
                      </p>
                    </div>
                    <Button
                      className="shrink-0"
                      disabled={importing}
                      onClick={() => importFileRef.current?.click()}
                    >
                      {importing ? "读取中…" : "选择文件"}
                    </Button>
                  </div>

                  {pendingPkcs12 ? (
                    <div className="mt-2 flex gap-2">
                      <TextInput
                        type="password"
                        value={p12Password}
                        placeholder="PKCS#12 口令"
                        onChange={(event) => setP12Password(event.target.value)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter") void unlockPkcs12();
                        }}
                      />
                      <Button variant="primary" className="shrink-0" disabled={importing} onClick={() => void unlockPkcs12()}>
                        解锁
                      </Button>
                    </div>
                  ) : null}

                  {importNote ? (
                    <p
                      className={`mt-2 text-[11px] leading-relaxed ${
                        importNote.tone === "err" ? "text-rose-600" : "text-emerald-700"
                      }`}
                    >
                      {importNote.text}
                    </p>
                  ) : null}

                  {imported?.certPem && imported?.keyPem ? (
                    <div className="mt-2 flex flex-wrap items-center gap-2 border-t border-zinc-200/70 pt-2">
                      <span className="text-[11px] text-zinc-500">
                        {imported.notAfter ? `有效期至 ${formatDate(imported.notAfter)}` : ""}
                        {imported.keyMatchesCert ? " · 私钥配对已验证" : ""}
                      </span>
                      <Button className="px-2 py-1 text-[11px]" onClick={() => void saveImportedCa()}>
                        存入本地 CA 库
                      </Button>
                    </div>
                  ) : null}

                  {imported?.notes?.length ? (
                    <ul className="mt-1.5 space-y-0.5">
                      {imported.notes.map((note) => (
                        <li key={note} className="text-[11px] leading-relaxed text-zinc-400">
                          · {note}
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </div>

                {savedCas.length > 0 ? (
                  <div className="space-y-1">
                    <div className="flex gap-2">
                      <Select value={selectedCaId} onChange={(event) => applySavedCa(event.target.value)}>
                        <option value="">从本地 CA 库选择…</option>
                        {savedCas.map((ca) => (
                          <option key={ca.id} value={ca.id}>
                            {ca.name}
                            {ca.notAfter < PAGE_LOADED_AT ? "（已过期）" : ""}
                          </option>
                        ))}
                      </Select>
                      <Button
                        variant="ghost"
                        className="shrink-0 px-2"
                        disabled={!selectedCaId}
                        onClick={() => void removeSavedCa()}
                      >
                        删除
                      </Button>
                    </div>
                    <p className="text-[11px] text-zinc-400">
                      保存在浏览器存储中，清理浏览器数据会一并删除。
                    </p>
                  </div>
                ) : null}

                <Field label="CA 证书（PEM）">
                  <Textarea
                    rows={3}
                    value={caCertPem}
                    placeholder="-----BEGIN CERTIFICATE-----"
                    onChange={(event) => setCaCertPem(event.target.value)}
                  />
                </Field>
                <Field label="CA 私钥（PEM，支持 PKCS#8 / PKCS#1 / SEC1）">
                  <Textarea
                    rows={3}
                    value={caKeyPem}
                    placeholder="-----BEGIN PRIVATE KEY-----"
                    onChange={(event) => setCaKeyPem(event.target.value)}
                  />
                </Field>
              </section>
            ) : null}

            <section className="space-y-2 border-t border-zinc-100 pt-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-medium text-zinc-900">生成前自检</h3>
                <span className="text-[11px] text-zinc-400">{checks.length} 项</span>
              </div>
              <ul className="space-y-1.5">
                {checks.map((check, index) => {
                  const style = LEVEL_STYLES[check.level];
                  return (
                    <li key={`${check.title}-${index}`} className="flex gap-2">
                      <span className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${style.dot}`} />
                      <div>
                        <p className={`text-xs ${style.text}`}>{check.title}</p>
                        {check.detail ? (
                          <p className="mt-0.5 text-[11px] leading-relaxed text-zinc-400">{check.detail}</p>
                        ) : null}
                      </div>
                    </li>
                  );
                })}
              </ul>
            </section>

            <div className="space-y-2 border-t border-zinc-100 pt-4">
              <Button variant="primary" className="w-full py-2.5" disabled={busy || hasError} onClick={generate}>
                {busy ? "正在生成密钥与证书…" : "生成证书"}
              </Button>
              {hasError ? (
                <p className="text-center text-[11px] text-rose-600">请先处理上面标记为「必须处理」的问题</p>
              ) : (
                <p className="text-center text-[11px] text-zinc-400">
                  RSA 4096 的密钥生成可能需要数秒
                </p>
              )}
              {error ? <p className="text-center text-[11px] text-rose-600">{error}</p> : null}
            </div>
          </div>
        </Card>

        <div className="min-w-0 lg:sticky lg:top-20">
          <ResultPanel result={result} baseName={baseName} onUseAsCa={useAsCa} />
        </div>
      </div>

      <Inspector />
    </div>
  );
}
