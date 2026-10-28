export interface StoredCa {
  id: string;
  name: string;
  certPem: string;
  keyPem: string;
  createdAt: number;
  notAfter: number;
}

const DB_NAME = "make-cert";
const DB_VERSION = 1;
const STORE = "ca";

export function isVaultSupported(): boolean {
  return typeof indexedDB !== "undefined";
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (!isVaultSupported()) {
      reject(new Error("当前浏览器环境不支持 IndexedDB，无法使用本地 CA 库。"));
      return;
    }
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(STORE)) {
        database.createObjectStore(STORE, { keyPath: "id" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("无法打开本地数据库"));
  });
}

async function run<T>(
  mode: IDBTransactionMode,
  operation: (store: IDBObjectStore) => IDBRequest,
): Promise<T> {
  const database = await openDatabase();
  return new Promise<T>((resolve, reject) => {
    const transaction = database.transaction(STORE, mode);
    const request = operation(transaction.objectStore(STORE));
    request.onsuccess = () => resolve(request.result as T);
    request.onerror = () => reject(request.error ?? new Error("本地数据库操作失败"));
    transaction.oncomplete = () => database.close();
  });
}

export async function listCas(): Promise<StoredCa[]> {
  const items = await run<StoredCa[]>("readonly", (store) => store.getAll());
  return items.sort((a, b) => b.createdAt - a.createdAt);
}

export async function saveCa(ca: StoredCa): Promise<void> {
  await run("readwrite", (store) => store.put(ca));
}

export async function deleteCa(id: string): Promise<void> {
  await run("readwrite", (store) => store.delete(id));
}

export async function clearCas(): Promise<void> {
  await run("readwrite", (store) => store.clear());
}
