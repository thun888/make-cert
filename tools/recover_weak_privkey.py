#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recover_weak_privkey.py  —  从 PEM 证书 / 公钥文件中"从最小的开始"遍历求出弱私钥

原理
----
EC 公钥就是私钥标量的倍点:  Q = d * G
若私钥 d 很小（弱随机数、测试密钥、硬件缺陷等），就可以直接从小到大试:
    d = 1, 2, 3, ...  逐个算 d*G，与公钥点比对，命中即为私钥。

两种模式
--------
  linear (默认)   真正"从最小的开始"逐个升序尝试，所有证书共用一趟扫描，非常快。
  bsgs            宝宝步-巨步（baby-step giant-step），用 O(sqrt(range)) 的代价搜很大范围，
                  适合 d 有 32~48 bit 的情形；等价于把升序空间整体覆盖，但快几个数量级。

用法
----
  python tools/recover_weak_privkey.py "D:\\Downloads\\Compressed\\proof\\pem"
  python tools/recover_weak_privkey.py <目录> --limit 1000000
  python tools/recover_weak_privkey.py <目录> --mode bsgs --max-bits 40 --mb 16
  python tools/recover_weak_privkey.py <目录> --dry-run        # 只解析，不求解

依赖: pycryptodome（椭圆曲线点运算） + cryptography（解析证书、导出私钥）
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

try:
    from Crypto.PublicKey import _point          # pycryptodome: C 实现的曲线点运算
except ImportError:                              # pragma: no cover
    sys.exit("缺少依赖，请先执行:  pip install pycryptodome")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# cryptography 曲线名 -> (pycryptodome 曲线名, cryptography 曲线类)
CURVE_MAP = {
    "secp192r1": ("P-192", ec.SECP192R1),
    "secp224r1": ("P-224", ec.SECP224R1),
    "secp256r1": ("P-256", ec.SECP256R1),
    "secp384r1": ("P-384", ec.SECP384R1),
    "secp521r1": ("P-521", ec.SECP521R1),
}

CERT_SUFFIXES = (".crt.pem", ".cert.pem", ".crt", ".cer", ".pem")
SIG_SUFFIXES = (".sig", ".signature")


# --------------------------------------------------------------------------- #
# 解析
# --------------------------------------------------------------------------- #
class Target:
    """一个待求解的公钥目标"""

    def __init__(self, path: Path, pub, py_name: str, py_curve_cls):
        self.path = path
        self.pub = pub
        self.curve_name = pub.curve.name
        self.py_name = py_name
        self.py_curve_cls = py_curve_cls
        nums = pub.public_numbers()
        self.x = nums.x
        self.y = nums.y
        self.d: int | None = None
        self.elapsed = 0.0
        self.sig_hash: str | None = None

    @property
    def name(self) -> str:
        n = self.path.name
        for suf in CERT_SUFFIXES:
            if n.lower().endswith(suf):
                return n[: -len(suf)]
        return self.path.stem

    @property
    def key_bits(self) -> str:
        return f"{self.d.bit_length()} bits" if self.d else "-"


def load_target(path: Path) -> Target:
    data = path.read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in data:
        pub = x509.load_pem_x509_certificate(data).public_key()
    else:
        pub = serialization.load_pem_public_key(data)

    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise TypeError(f"不是 EC 公钥（{type(pub).__name__}），本脚本只处理椭圆曲线弱私钥")
    curve_name = pub.curve.name
    if curve_name not in CURVE_MAP:
        raise TypeError(f"不支持的曲线 {curve_name}")
    py_name, py_curve_cls = CURVE_MAP[curve_name]
    return Target(path, pub, py_name, py_curve_cls)


def collect_files(directory: Path, include_pub: bool) -> list[Path]:
    files, seen_names = [], set()
    for p in sorted(directory.iterdir()):
        if not p.is_file():
            continue
        low = p.name.lower()
        if low.endswith(".pub.pem"):
            if include_pub:
                files.append(p)
            continue
        if low.endswith(CERT_SUFFIXES) and low.endswith(".pem"):
            files.append(p)
    # 证书 + 同名公钥去重：优先证书
    out = []
    for p in files:
        try:
            t = load_target(p)
        except Exception:
            continue
        if t.name in seen_names:
            continue
        seen_names.add(t.name)
        out.append(p)
    return out


# --------------------------------------------------------------------------- #
# 求解: 线性升序（默认）
# --------------------------------------------------------------------------- #
def solve_linear(targets: list[Target], limit: int, quiet: bool = False) -> None:
    """
    真正意义上的"从最小的 d 开始遍历"：
    所有证书共用同一趟 d = 1, 2, 3, ... 的扫描，命中一个就摘掉一个。
    """
    by_curve: dict[str, list[Target]] = {}
    for t in targets:
        by_curve.setdefault(t.py_name, []).append(t)

    for py_name, group in by_curve.items():
        curve = _point._curves[py_name]
        G = curve.G
        pending = {t.x: t for t in group}
        if not quiet:
            print(f"[*] {py_name}: 升序遍历 d = 1 … {limit:,}  ({len(pending)} 个目标)")

        t0 = time.time()
        P = G * 1                    # d * G，从 d = 1 开始
        d = 1
        last = t0
        while pending and d <= limit:
            hit = pending.get(int(P.x))
            if hit is not None and hit.d is None:
                if G * d == _point.EccPoint(hit.x, hit.y, curve=py_name):
                    hit.d = d
                    hit.elapsed = time.time() - t0
                    print(f"    [{len(group) - len(pending) + 1}/{len(group)}] {hit.name}: "
                          f"d = {d}  ({hit.key_bits})")
                    del pending[hit.x]
            P += G
            d += 1

            now = time.time()
            if not quiet and now - last >= 5.0:
                last = now
                print(f"    ... 已试到 d = {d:,}", end="\r")

        if not quiet and pending:
            print()
        for t in pending.values():
            t.elapsed = time.time() - t0


# --------------------------------------------------------------------------- #
# 求解: BSGS（大范围加速）
# --------------------------------------------------------------------------- #
class BSGS:
    """小步表 table[x(j*G)] = j；大步 Q - i*B*G。单条曲线的表可复用"""

    def __init__(self, py_name: str, mb: int = 20, quiet: bool = False):
        self.py_name = py_name
        self.curve = _point._curves[py_name]
        self.G = self.curve.G
        self.n = int(self.curve.order)
        self.bits = self.n.bit_length()
        self.mb = mb
        self.B = 1 << mb
        self.quiet = quiet
        self.table: dict[int, int] = {}

    def build(self) -> None:
        if self.table:
            return
        t0 = time.time()
        negG = -self.G
        P = self.G * self.B
        table = self.table
        for j in range(self.B - 1, 0, -1):
            P += negG
            # 用 x 的低 64 bit 做键：够区分，且比整个 384bit 整数更快
            table[int(P.x) & 0xFFFFFFFFFFFFFFFF] = j
        if not self.quiet:
            print(f"[*] 小步表 2^{self.mb} 项构建完成，耗时 {time.time() - t0:.1f}s")

    def search(self, target: Target, max_bits: int) -> int | None:
        self.build()
        # 注意: EccPoint 的 += 是原地修改，所以这里只留坐标用于复核，避免别名污染
        tx, ty = target.x, target.y
        M = 1 << max(0, max_bits - self.mb)
        step = -(self.G * self.B)
        table = self.table
        R = _point.EccPoint(tx, ty, curve=self.py_name)
        t0 = time.time()
        for i in range(M):
            if not R.is_point_at_infinity():
                j = table.get(int(R.x) & 0xFFFFFFFFFFFFFFFF)
                if j is not None:
                    d = i * self.B + j
                    if d:
                        P = self.G * d
                        if int(P.x) == tx and int(P.y) == ty:
                            target.d = d
                            target.elapsed = time.time() - t0
                            return d
            R += step
        target.elapsed = time.time() - t0
        return None


def solve_bsgs(targets: list[Target], max_bits: int, mb: int, quiet: bool = False) -> None:
    by_curve: dict[str, list[Target]] = {}
    for t in targets:
        by_curve.setdefault(t.py_name, []).append(t)

    for py_name, group in by_curve.items():
        solver = BSGS(py_name, mb, quiet=quiet)
        for t in group:
            solver.search(t, max_bits)
            if t.d is not None:
                print(f"    {t.name}: d = {t.d}  ({t.key_bits})  用时 {t.elapsed:.1f}s")
            elif not quiet:
                print(f"    {t.name}: 2^{max_bits} 范围内未找到  用时 {t.elapsed:.1f}s")


# --------------------------------------------------------------------------- #
# 校验 / 导出
# --------------------------------------------------------------------------- #
def message_and_sigs(root: Path) -> tuple[bytes | None, dict[str, Path]]:
    """在目录本身或其兄弟目录里找 message.txt 与 *.sig"""
    sigs: dict[str, Path] = {}
    msg = None
    for base in (root, root.parent / "proof", root.parent):
        if not base.is_dir():
            continue
        if msg is None and (base / "message.txt").is_file():
            msg = (base / "message.txt").read_bytes()
        for p in base.iterdir():
            if p.is_file() and p.suffix.lower() in SIG_SUFFIXES:
                sigs.setdefault(p.stem, p)
    return msg, sigs


def verify_signature(target: Target, sig_path: Path, message: bytes) -> str | None:
    """用证书里的公钥校验该证书自己的签名，返回命中的哈希算法名"""
    if not sig_path.is_file():
        return None
    sig = sig_path.read_bytes()
    for hname, h in (("SHA-384", hashes.SHA384()), ("SHA-256", hashes.SHA256()),
                     ("SHA-512", hashes.SHA512()), ("SHA-1", hashes.SHA1())):
        try:
            target.pub.verify(sig, message, ec.ECDSA(h))
            return hname
        except Exception:
            continue
    return None


def export_key(target: Target, out_dir: Path) -> Path:
    key = ec.derive_private_key(target.d, target.py_curve_cls())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{target.name}.key.pem"
    out.write_bytes(pem)
    return out


# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(
        description="从最小的 d 开始遍历，求解证书/公钥文件中的弱 EC 私钥",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("directory", help="包含 *.crt.pem / *.pub.pem 的目录")
    ap.add_argument("--mode", choices=("linear", "bsgs"), default="linear",
                    help="linear=升序逐个试；bsgs=大范围加速")
    ap.add_argument("--limit", type=int, default=1 << 20,
                    help="linear 模式的升序上限（试到 d = limit）")
    ap.add_argument("--max-bits", type=int, default=40,
                    help="bsgs 模式的搜索上限 2^N")
    ap.add_argument("--mb", type=int, default=20,
                    help="bsgs 模式小步表大小 2^mb（越大越占内存、大步越少）")
    ap.add_argument("--out", default=None, help="私钥输出目录（默认 <目录>/recovered_keys）")
    ap.add_argument("--include-pub", action="store_true", help="同时把 *.pub.pem 作为目标")
    ap.add_argument("--dry-run", action="store_true", help="只解析并列出目标，不求解")
    ap.add_argument("--no-export", action="store_true", help="不写出私钥文件")
    ap.add_argument("--quiet", action="store_true", help="精简输出")
    args = ap.parse_args()

    root = Path(args.directory).expanduser().resolve()
    if not root.is_dir():
        print(f"目录不存在: {root}")
        return 2

    files = collect_files(root, args.include_pub)
    if not files:
        print(f"{root} 下没有找到证书/公钥文件")
        return 2

    targets: list[Target] = []
    for f in files:
        try:
            targets.append(load_target(f))
        except Exception as e:
            print(f"[!] 跳过 {f.name}: {e}")
    if not targets:
        return 1

    max_curve_bits = max(1, targets[0].py_curve_cls().key_size)

    print(f"[*] 目标目录: {root}")
    print(f"[*] 目标数量: {len(targets)}    曲线: {targets[0].curve_name} "
          f"(私钥标量理论上限 {max_curve_bits} bit)")
    print()

    print(f"  {'证书名称':<24}{'曲线':<14}{'公钥 X（前 16 hex）'}")
    print("  " + "-" * 62)
    for t in targets:
        print(f"  {t.name[:23]:<24}{t.curve_name:<14}{t.x:016x}…")
    print()

    if args.dry_run:
        return 0

    msg, sigs = message_and_sigs(root)

    t_all = time.time()
    if args.mode == "linear":
        print(f"[*] 模式: 升序线性遍历（d = 1, 2, 3, … ≤ {args.limit:,}）")
        solve_linear(targets, args.limit, quiet=args.quiet)
    else:
        print(f"[*] 模式: BSGS（d < 2^{args.max_bits}，小步表 2^{args.mb}）")
        solve_bsgs(targets, args.max_bits, args.mb, quiet=args.quiet)

    found = [t for t in targets if t.d is not None]
    out_dir = Path(args.out) if args.out else root / "recovered_keys"

    print()
    print("  " + "-" * 62)
    for t in found:
        if msg is not None and t.name in sigs:
            t.sig_hash = verify_signature(t, sigs[t.name], msg)
        extra = f"签名校验通过（{t.sig_hash}）" if t.sig_hash else ""
        line = f"  {t.name:<28} d = {t.d:<6} ({t.key_bits})"
        print(f"{line:<58}{extra}")
        if not args.no_export:
            kp = export_key(t, out_dir)
            print(f"  {'':<28} 私钥 -> {kp}")

    print()
    print(f"[*] 共 {len(found)}/{len(targets)} 个私钥还原成功，总耗时 {time.time() - t_all:.1f}s")
    if len(found) < len(targets):
        missing = len(targets) - len(found)
        print(f"[!] {missing} 个未找到：可提高 --limit，或改用 "
              f"--mode bsgs --max-bits 40/48 扩大范围")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
