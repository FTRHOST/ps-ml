#!/usr/bin/env python3
"""
rootcmd.py — jalankan perintah shell di Android SEBAGAI ROOT lewat frida-server.

Kenapa begini: device ini tidak punya binary `su` dan `adb root` ditolak
(production build), tetapi frida-server berjalan sebagai uid 0. Spawn dari
frida-server mewarisi uid server, sehingga `sh -c` yang kita spawn ikut root.

Pemakaian:
    python3 tools/rootcmd.py "id"
    python3 tools/rootcmd.py -f "iptables -t nat -L OUTPUT -n"

Hanya untuk perangkat uji milik sendiri (PRD N6 / CLAUDE.md butir 5).
"""
import subprocess
import sys
import time
import uuid

import frida

FRIDA_ADDR = "127.0.0.1:2626"
REMOTE_OUT = "/data/local/tmp/rootcmd.out"


def run(cmd: str, timeout: float = 20.0) -> int:
    dev = frida.get_device_manager().add_remote_device(FRIDA_ADDR)
    # Bersihkan file hasil lama supaya tidak tertukar dengan keluaran sebelumnya.
    subprocess.run(
        ["adb", "shell", f"rm -f {REMOTE_OUT}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Dibungkus `{ ... }` supaya SEMUA perintah (bukan hanya yang terakhir)
    # ikut dialihkan ke file hasil; `$?` = exit status dari grup terakhir.
    wrapped = f"{{ {cmd} ; }} > {REMOTE_OUT} 2>&1; echo __EXIT_$? >> {REMOTE_OUT}"
    pid = dev.spawn(["/system/bin/sh", "-c", wrapped])
    dev.resume(pid)

    deadline = time.time() + timeout
    while time.time() < deadline:
        res = subprocess.run(
            ["adb", "shell", f"cat {REMOTE_OUT} 2>/dev/null"],
            capture_output=True,
            text=True,
        )
        body = res.stdout or ""
        if "__EXIT_" in body:
            code_line = [l for l in body.splitlines() if l.startswith("__EXIT_")][-1]
            code = int(code_line.split("_")[-1])
            text = "\n".join(
                l for l in body.splitlines() if not l.startswith("__EXIT_")
            )
            print(text)
            return code
        time.sleep(0.2)
    print(f"[!] timeout setelah {timeout}s; perintah mungkin masih berjalan", file=sys.stderr)
    return 124


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 2
    if args[0] == "-f":
        # mode file: jalankan isi file sebagai skrip shell
        with open(args[1], "r", encoding="utf-8") as fh:
            script = fh.read().strip().replace("\n", " ; ")
        return run(script)
    return run(" ".join(args))


if __name__ == "__main__":
    sys.exit(main())
