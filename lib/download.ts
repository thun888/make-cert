export function download(filename: string, data: string | Uint8Array, mime: string) {
  const blob = new Blob([data as BlobPart], { type: mime });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export function sanitizeBaseName(value: string): string {
  return (
    value
      .trim()
      .replace(/^\*\./, "wildcard-")
      .replace(/[^a-zA-Z0-9.-]/g, "-")
      .replace(/-{2,}/g, "-")
      .replace(/^[-.]+|[-.]+$/g, "")
      .toLowerCase() || "certificate"
  );
}
