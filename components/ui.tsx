"use client";

import { useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-2xl border border-zinc-200 bg-white ${className}`}>{children}</div>
  );
}

export function CardHeader({
  title,
  description,
  aside,
}: {
  title: string;
  description?: string;
  aside?: ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-zinc-100 px-4 py-4 sm:px-5">
      <div>
        <h2 className="text-sm font-medium text-zinc-900">{title}</h2>
        {description ? <p className="mt-1 text-xs leading-relaxed text-zinc-500">{description}</p> : null}
      </div>
      {aside}
    </div>
  );
}

export function Field({
  label,
  hint,
  children,
  className = "",
}: {
  label: string;
  hint?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <label className={`flex flex-col gap-1.5 ${className}`}>
      <span className="text-xs font-medium text-zinc-600">{label}</span>
      {children}
      {hint ? <span className="text-[11px] leading-relaxed text-zinc-400">{hint}</span> : null}
    </label>
  );
}

const controlClass =
  "w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-zinc-400 focus:ring-2 focus:ring-zinc-900/5 disabled:bg-zinc-50 disabled:text-zinc-400";

export function TextInput(props: InputHTMLAttributes<HTMLInputElement>) {
  const { className = "", ...rest } = props;
  return <input {...rest} className={`${controlClass} ${className}`} />;
}

export function Select(props: SelectHTMLAttributes<HTMLSelectElement>) {
  const { className = "", children, ...rest } = props;
  return (
    <select {...rest} className={`${controlClass} ${className}`}>
      {children}
    </select>
  );
}

export function Textarea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const { className = "", ...rest } = props;
  return (
    <textarea
      {...rest}
      spellCheck={false}
      className={`${controlClass} font-mono text-[11px] leading-relaxed ${className}`}
    />
  );
}

type ButtonVariant = "primary" | "secondary" | "ghost";

const buttonVariants: Record<ButtonVariant, string> = {
  primary:
    "bg-zinc-900 text-white hover:bg-zinc-800 disabled:bg-zinc-300 disabled:text-zinc-500",
  secondary:
    "border border-zinc-200 bg-white text-zinc-700 hover:border-zinc-300 hover:bg-zinc-50 disabled:text-zinc-400",
  ghost: "text-zinc-500 hover:bg-zinc-100 hover:text-zinc-900",
};

export function Button({
  variant = "secondary",
  className = "",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  return (
    <button
      {...rest}
      className={`inline-flex items-center justify-center gap-1.5 rounded-lg px-3 py-2 text-sm font-medium transition disabled:cursor-not-allowed ${buttonVariants[variant]} ${className}`}
    />
  );
}

export function Badge({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: "neutral" | "success" | "warn" | "danger" | "info";
}) {
  const tones = {
    neutral: "bg-zinc-100 text-zinc-600",
    success: "bg-emerald-50 text-emerald-700",
    warn: "bg-amber-50 text-amber-700",
    danger: "bg-rose-50 text-rose-700",
    info: "bg-sky-50 text-sky-700",
  };
  return (
    <span
      className={`inline-flex shrink-0 items-center whitespace-nowrap rounded-full px-2 py-0.5 text-[11px] font-medium ${tones[tone]}`}
    >
      {children}
    </span>
  );
}

export function Segmented<T extends string>({
  value,
  options,
  onChange,
}: {
  value: T;
  options: Array<{ value: T; label: string }>;
  onChange: (value: T) => void;
}) {
  return (
    <div className="flex gap-1 rounded-xl bg-zinc-100 p-1">
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          onClick={() => onChange(option.value)}
          className={`flex-1 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
            value === option.value
              ? "bg-white text-zinc-900 shadow-sm"
              : "text-zinc-500 hover:text-zinc-800"
          }`}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

export function CodeBlock({
  code,
  onDownload,
  filename,
  wrap = false,
}: {
  code: string;
  onDownload?: () => void;
  filename?: string;
  /** 长行（如 PEM）在窄屏上换行显示，避免把页面撑宽 */
  wrap?: boolean;
}) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="w-full min-w-0 max-w-full">
      {/* 操作按钮停在内容上方的一行里，不再占用正文宽度，正文可以整行铺满 */}
      <div className="mb-1.5 flex items-center justify-end gap-1">
        <button
          type="button"
          onClick={copy}
          className="rounded-md bg-white px-2 py-1 text-[11px] font-medium text-zinc-600 shadow-sm ring-1 ring-zinc-200 transition hover:bg-zinc-50 hover:text-zinc-900"
        >
          {copied ? "已复制" : "复制"}
        </button>
        {onDownload ? (
          <button
            type="button"
            onClick={onDownload}
            className="rounded-md bg-white px-2 py-1 text-[11px] font-medium text-zinc-600 shadow-sm ring-1 ring-zinc-200 transition hover:bg-zinc-50 hover:text-zinc-900"
          >
            下载
          </button>
        ) : null}
      </div>
      <pre
        className={`max-h-[380px] w-full min-w-0 max-w-full overflow-auto rounded-xl border border-zinc-200 bg-zinc-50 p-3 font-mono text-[11px] leading-relaxed text-zinc-700 ${
          wrap ? "whitespace-pre-wrap break-all lg:whitespace-pre lg:break-normal" : ""
        }`}
      >
        <code>{code}</code>
      </pre>
      {filename ? (
        <p className="mt-1.5 text-[11px] text-zinc-400">文件名：{filename}</p>
      ) : null}
    </div>
  );
}
