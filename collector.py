import frida
import json
import os
import sys
import time
import subprocess
from datetime import datetime

OUTPUT_DIR = "mlbb_captured_tags"
TAG_LOG = os.path.join(OUTPUT_DIR, "tags.jsonl")
OPCODE_LOG = os.path.join(OUTPUT_DIR, "opcodes.jsonl")
CLASS_LOG = os.path.join(OUTPUT_DIR, "unpack_classes.jsonl")
WIRE_LOG = os.path.join(OUTPUT_DIR, "wire_opcodes.jsonl")
BODY_LOG = os.path.join(OUTPUT_DIR, "wire_bodies.jsonl")
SDP_LOG = os.path.join(OUTPUT_DIR, "sdp_bodies.jsonl")
MSGID_LOG = os.path.join(OUTPUT_DIR, "wire_msgids.jsonl")
PROCESS_KEYWORD = ":UnityKillsMe"
# Tag visit sangat banyak (jutaan baris). Default: jangan disimpan agar IO
# ringan; set SAVE_TAGS=1 bila memang perlu analisis field per tag.
SAVE_TAGS = os.environ.get("SAVE_TAGS") == "1"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def on_message(message, data):
    mtype = message["type"]

    if mtype == "send":
        payload = message["payload"]
        kind = payload.get("kind", "packet")

        # --- Event tag (SdpUnpackerImpl.visit): digabung ke satu file jsonl ---
        if kind == "tag":
            if not SAVE_TAGS:
                return
            with open(TAG_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False) + "\n")
            return

        # --- Debug sekali dari agent (mis. bentuk argumen Unpack) ---
        if kind == "debug":
            print(f"[agent-debug] {json.dumps(payload, ensure_ascii=False)}")
            return

        # --- Peta opcode -> class (PackUtil.Unpack) ---
        if kind == "opcode_map":
            with open(OPCODE_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False) + "\n")
            return

        # --- Event class hasil Unpack (untuk dipasangkan dengan opcode wire) ---
        if kind == "unpack_class":
            with open(CLASS_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False) + "\n")
            return

        # --- Event opcode wire per paket masuk ---
        if kind == "wire_opcode":
            with open(WIRE_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False) + "\n")
            return

        # --- Pasangan opcode wire + messageid dari ReturnMsg DecodeMsgBody ---
        if kind == "wire_msgid":
            with open(MSGID_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False) + "\n")
            return

        # --- Pasangan class_name + body SDP dari bytesToSdp(byte[], Type) ---
        if kind == "sdp_body":
            with open(SDP_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False) + "\n")
            return

        # --- Pasangan opcode wire + body SDP dari amplop RspProto/ReqProto ---
        if kind == "wire_body":
            with open(BODY_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False) + "\n")
            return

        # --- Paket RECV / SEND: satu file JSON per paket ---
        direction = payload.get("direction")
        opcode = payload.get("opcode")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"{OUTPUT_DIR}/{direction}_{opcode}_{timestamp}.json"

        record = {
            "direction": direction,
            "opcode": opcode,
            "opcode_name": payload.get("opcode_name"),
            "class_name": payload.get("class_name"),
            "seq": payload.get("seq"),
            "rsp_code": payload.get("rsp_code"),
            "timestamp": payload.get("timestamp"),
            "fields": payload.get("fields", {}),
            "raw_hex": data.hex() if data else "",
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=4, ensure_ascii=False)
        print(f"[SAVED] {direction} {opcode} ({record['opcode_name']}) -> {filename}")

    elif mtype == "log":
        print(f"[agent] {message.get('payload')}")

    elif mtype == "error":
        print(f"[ERROR] {message.get('stack') or message}")


def find_pid():
    """Cari PID proses Android yang namanya mengandung PROCESS_KEYWORD.
    Parsing dilakukan di Python (tanpa grep/awk) supaya jalan juga di Windows."""
    try:
        out = subprocess.check_output(["adb", "shell", "ps", "-A"]).decode("utf-8", "ignore")
    except Exception:
        return None
    for line in out.splitlines():
        if PROCESS_KEYWORD in line:
            parts = line.split()
            if len(parts) > 1 and parts[1].isdigit():
                return int(parts[1])
    return None


def main():
    remote_address = "127.0.0.1:2626"

    # 1. ADB + port forwarding
    try:
        print("[*] Menginisialisasi koneksi ADB...")
        subprocess.run(["adb", "devices"], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["adb", "forward", "tcp:2626", "tcp:2626"], check=True, stdout=subprocess.DEVNULL)
        print("[+] ADB Port Forwarding berhasil!")
    except Exception as e:
        print(f"[!] Gagal menjalankan ADB: {e}. Pastikan ADB terinstall.")
        return

    # 2. Tunggu proses target
    print(f"[*] Menunggu proses '{PROCESS_KEYWORD}' aktif...")
    target_pid = None
    while not target_pid:
        target_pid = find_pid()
        if not target_pid:
            time.sleep(0.5)
    print(f"[+] Target ditemukan! PID: {target_pid}")

    # 3. Koneksi ke frida-server
    print(f"[*] Menghubungkan Frida ke {remote_address}...")
    try:
        device = frida.get_device_manager().add_remote_device(remote_address)
    except Exception:
        device = frida.get_remote_device()

    # 4. Attach + load agent
    script_path = next(
        (p for p in ("dist/agent.js", "mlbb_packet_dump.js") if os.path.exists(p)), None
    )
    if not script_path:
        print("[!] dist/agent.js tidak ditemukan. Jalankan dulu: npm run build")
        return

    session = None
    try:
        # Cold start Unity membuat proses belum siap di-attach (frida timeout).
        # Ulangi beberapa kali sebelum menyerah.
        last_error = None
        for attempt in range(1, 11):
            try:
                print(f"[*] Attach ke PID {target_pid} dengan {script_path} (percobaan {attempt})...")
                session = device.attach(target_pid)
                with open(script_path, "r", encoding="utf-8") as f:
                    script = session.create_script(f.read())
                script.on("message", on_message)
                script.load()
                break
            except Exception as e:
                last_error = e
                if session:
                    try:
                        session.detach()
                    except Exception:
                        pass
                    session = None
                time.sleep(3)
        else:
            raise last_error if last_error else RuntimeError("attach gagal")
        print("[*] Berhasil! Memantau paket masuk & keluar. Tekan Ctrl+C untuk berhenti.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Dihentikan.")
    except Exception as e:
        print(f"[!] Gagal attach atau memuat skrip: {e}")
    finally:
        if session:
            try:
                session.detach()
            except Exception:
                pass


if __name__ == "__main__":
    main()
