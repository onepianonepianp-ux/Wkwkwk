#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WEIRDMARKET - Combined Checker
Fitur:
  1. CEK VALID
     - Single Device ID
     - Bulk Device ID
  2. CEK BAN
     - Single Device ID
     - Bulk Device ID
  3. EXIT

Logic valid berasal dari weird_valid.py.
Logic ban berasal dari weird_ban.py.
"""

import socket
import zlib
import zstandard as zstd
import datetime
import struct
import os
import concurrent.futures
import threading
import re
from pathlib import Path
from enum import Enum
from typing import Any, Tuple

from rich.console import Console
from rich.prompt import Prompt, IntPrompt
from rich.table import Table
from Crypto.Cipher import AES
from colorama import init, Fore, Style, Back

init(autoreset=True)

# Rich console used by the split/device-manager features.
console = Console()

# ── DEVICE/SPLIT CONFIG ─────────────────────────────────────────────
# Device IDs accepted by the split/device-manager: and_... or ios_...
DEVICE_RE = re.compile(r"(?i)(?:and_|ios_)[A-Za-z0-9_-]+")

# All split/export output is stored beside this script.
RESULTS = Path(__file__).resolve().parent / "results"

# ── GLOBAL MODE FLAGS ────────────────────────────────────────────────
DEBUG_MODE = False  # Set to True to see the detailed packet logs
RESULTS_FILE = "results_weiRd.txt" # File kung saan isesave ang hits

# ── DEBUG HELPERS ────────────────────────────────────────────────────
def dbg(label, data=None, color=Fore.MAGENTA):
    """Print a debug message only when DEBUG_MODE is on."""
    if not DEBUG_MODE:
        return
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    if data is None:
        print(f"{color}[DBG {ts}] {label}{Style.RESET_ALL}")
    else:
        print(f"{color}[DBG {ts}] {label}{Style.RESET_ALL}")
        if isinstance(data, (bytes, bytearray)):
            hex_str = data.hex()
            for i in range(0, len(hex_str), 64):
                print(f"  {Fore.CYAN}{hex_str[i:i+64]}{Style.RESET_ALL}")
        elif isinstance(data, dict):
            for k, v in data.items():
                print(f"  {Fore.CYAN}[{k}] => {repr(v)[:120]}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.CYAN}{repr(data)[:200]}{Style.RESET_ALL}")

AES_KEY = bytes.fromhex('f5a193d50ade553e9835595f5cd75ddd')
AES_IV = b'\x00' * 16

class SdpDataType(Enum):
    INTEGER_POSITIVE = 0
    INTEGER_NEGATIVE = 1
    FLOAT = 2
    DOUBLE = 3
    STRING = 4
    LIST = 5
    DICT = 6
    STRUCT_BEGIN = 7
    STRUCT_END = 8

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
                value = self._read_number()
                return tag, value
            elif data_type == SdpDataType.INTEGER_NEGATIVE:
                value = -self._read_number()
                return tag, value
            elif data_type == SdpDataType.FLOAT:
                value = self._read_number().to_bytes(4, 'little')
                value = struct.unpack("<f", value)[0]
                return tag, value
            elif data_type == SdpDataType.DOUBLE:
                value = self._read_number().to_bytes(8, 'little')
                value = struct.unpack("<d", value)[0]
                return tag, value
            elif data_type == SdpDataType.STRING:
                length = self._read_number()
                try:
                    value = self.data[self.offset:self.offset+length].decode('utf-8')
                except UnicodeDecodeError:
                    value = self.data[self.offset:self.offset+length]
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
        except Exception:
            raise SdpException("Error unpacking data")
    
    def __repr__(self):
        return f"SdpStruct({dict(self)})"

class BaseConnection:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sequence = 1
        self.socket = None
        self.queue_data = b''

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(5)
        self.socket.connect((self.host, self.port))

    def cleanup(self):
        if self.socket:
            self.socket.close()
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
        dbg(f"SEND  packet_id={id}  seq={self.sequence}  payload_bytes={len(sdp.data)}  compressed={len(buf)}")
        dbg("      SDP fields", dict(sdp))
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
            elif compression_type in (2, 3, 18):
                cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV)
                decrypted = cipher.decrypt(data[:-1] if len(data) % 16 != 0 else data)
                data = decrypted.rstrip(b'\x00')
                if compression_type == 3:
                    data = zlib.decompress(data)
                elif compression_type == 18:
                    data = zstd.decompress(data)

            result = SdpStruct(data)
            id = result.get(0)
            if id is None:
                return None, None

            res = result.get(6) or result.get(5)
            if not res or not isinstance(res, bytes):
                return id, None

            parsed_res = SdpStruct(res)
            dbg(f"RECV  id={id}  body_bytes={len(res)}  compression_type={compression_type}", color=Fore.CYAN)
            dbg("      SDP fields", dict(parsed_res), color=Fore.CYAN)
            return id, parsed_res

        except socket.timeout:
            return -1, None 
        except Exception:
            return None, None

class GameLogin(BaseConnection):
    def __init__(self, device_id):
        super().__init__('login.ml.youngjoygame.com', 30021)
        self.device_id = device_id
        
        parts = self.device_id.split('_')
        if len(parts) >= 2:
            device_info = parts[1]
            if len(parts) >= 3 and len(device_info) < 32:
                device_info = device_info + "_" + parts[2]
            
            if len(device_info) >= 32:
                self.imei_md5 = device_info[:32]
                self.android_id = device_info[32:48] if len(device_info) >= 48 else ""
                self.advertising_id = device_info[48:] if len(device_info) > 48 else ""
            else:
                self.imei_md5 = device_info
                self.android_id = ""
                self.advertising_id = ""
        else:
            self.imei_md5 = device_id
            self.android_id = ""
            self.advertising_id = ""
            
        self.channel = 'and_usa'
        self.client_version = '2.1.88.1202.1'

    def run(self):
        try:
            self.connect()
            dbg(f"LOGIN SERVER → sending packet 1  device_id={self.device_id[:30]}...")
            
            self.send_data(1, SdpStruct({
                0: self.device_id,
                1: f'gps_adid={self.advertising_id}&android_id={self.android_id}&device_unique_id={self.imei_md5}',
                2: self.client_version,
                3: self.channel,
                4: 'en'
            }))

            id, res = self.recv_data()
            dbg(f"LOGIN SERVER ← response id={id}")
            
            if id == 2 and res:
                account_id = res.get(0)
                session_key = res.get(1)
                zone_id = res[2][0] if 2 in res else None
                creation_ts = res.get(19, 0)
                
                short_session = f"{str(session_key)[:20]}..." if session_key else "None"
                dbg(f"LOGIN OK  account_id={account_id}  zone_id={zone_id}  session_key={short_session}  creation_ts={creation_ts}", color=Fore.GREEN)
                
                return account_id, zone_id
            else:
                dbg(f"LOGIN FAILED  id={id}", color=Fore.RED)
                return None, None
                
        except Exception as e:
            dbg(f"ERROR: {str(e)}", color=Fore.RED)
            return None, None
        finally:
            self.cleanup()




# ── BAN CHECKER NETWORK CONNECTION ───────────────────────────────────
class BanCheckerConnection:
    def __init__(self, device_id: str):
        self.host = 'login.ml.youngjoygame.com'
        self.port = 30021
        self.sequence = 1
        self.socket = None
        self.queue_data = b''
        self.device_id = device_id

        parts = device_id.split('_')
        device_info = parts[1] if len(parts) >= 2 else device_id
        if len(parts) >= 3 and len(device_info) < 32:
            device_info = device_info + "_" + parts[2]

        if len(device_info) >= 32:
            self.imei_md5 = device_info[:32]
            self.android_id = device_info[32:48] if len(device_info) >= 48 else ""
            self.advertising_id = device_info[48:] if len(device_info) > 48 else ""
        else:
            self.imei_md5 = device_id
            self.android_id = ""
            self.advertising_id = ""

        self.channel = 'and_usa'
        self.client_version = '2.1.61.1205.1'
        self.account_id = 0
        self.session_key = ''
        self.zone_id = 0
        self.game_server_host = ''
        self.game_server_port = 0

    def connect(self, host=None, port=None):
        if host:
            self.host = host
        if port:
            self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(5)
        self.socket.connect((self.host, self.port))

    def cleanup(self):
        if self.socket:
            self.socket.close()
            self.sequence = 1
            self.socket = None

    def send_data(self, pkt_id, sdp):
        packet = SdpStruct({
            0: pkt_id,
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
            elif compression_type in (2, 3, 18):
                cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV)
                data = cipher.decrypt(data[:-1] if len(data) % 16 != 0 else data)
                data = data.rstrip(b'\x00')
                if compression_type == 3:
                    data = zlib.decompress(data)
                elif compression_type == 18:
                    data = zstd.decompress(data)

            result = SdpStruct(data)
            pkt_id = result.get(0)
            if pkt_id is None:
                return None, None

            res = result.get(6) or result.get(5)
            if not res or not isinstance(res, bytes):
                return pkt_id, None

            return pkt_id, SdpStruct(res)

        except socket.timeout:
            return -1, None
        except Exception:
            return None, None


# ── BAN REASON MAPPING & HELPER ──────────────────────────────────────
BAN_REASONS = {

    "21": "Using Plug-in Apps to Compromise Competitive Fairness",

}

def inspect_for_ban(pkt_id, sdp_data):
    is_banned = False
    details = {}

    if sdp_data:
        def scan(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k == 'ban_reason':
                        code_str = str(v)
                        details['ban_code'] = code_str
                        details['reason_name'] = BAN_REASONS.get(code_str, "Using Plug-in Apps to Compromise Competitive Fairness")
                    elif k in ('ban_status', 'ban_time') or (isinstance(k, str) and 'ban' in k.lower()):
                        details[str(k)] = v
                    
                    if k == 'endtime_day': details['endtime_day'] = v
                    if k == 'endtime_hour': details['endtime_hour'] = v
                    if k == 'endtime_min': details['endtime_min'] = v
                    if k == 'endtime_sec': details['endtime_sec'] = v

                    if isinstance(v, (dict, list)): scan(v)
            elif isinstance(obj, list):
                for item in obj: scan(item)

        scan(dict(sdp_data))

    # STRICT CHECK: Banned ONLY if explicit 'endtime_day' exists
    if 'endtime_day' in details and details['endtime_day'] is not None:
        is_banned = True

    return is_banned, details



# ── UI DASAR ──────────────────────────────────────────────────────────
APP_NAME = "WEIRD TOOLS"
APP_CREDIT = "WEIRDMARKET"
APP_VERSION = "v2.1"
UI_WIDTH = 76

# Palette: cyan + violet + white. Tetap ringan dan jelas di Termux.
ACCENT = Fore.CYAN
ACCENT_2 = Fore.MAGENTA
TITLE = Fore.WHITE + Style.BRIGHT
MUTED = Fore.LIGHTBLACK_EX
SUCCESS = Fore.GREEN + Style.BRIGHT
WARNING = Fore.YELLOW + Style.BRIGHT
DANGER = Fore.RED + Style.BRIGHT


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def line(char="─", width=UI_WIDTH, color=MUTED):
    print(f"{color}{char * width}{Style.RESET_ALL}")


def center(text, color=Fore.WHITE, bold=False, width=UI_WIDTH):
    style = Style.BRIGHT if bold else ""
    print(f"{color}{style}{text[:width].center(width)}{Style.RESET_ALL}")


def _big_weird_tools():
    art = [
        "██╗    ██╗███████╗██╗██████╗ ██████╗",
        "██║    ██║██╔════╝██║██╔══██╗██╔══██╗",
        "██║ █╗ ██║█████╗  ██║██████╔╝██║  ██║",
        "██║███╗██║██╔══╝  ██║██╔══██╗██║  ██║",
        "╚███╔███╔╝███████╗██║██║  ██║██████╔╝",
        " ╚══╝╚══╝ ╚══════╝╚═╝╚═╝  ╚═╝╚═════╝ ",
        "        ████████╗ ██████╗  ██████╗ ██╗     ███████╗",
        "        ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝",
        "           ██║   ██║   ██║██║   ██║██║     ███████╗",
        "           ██║   ██║   ██║██║   ██║██║     ╚════██║",
        "           ██║   ╚██████╔╝╚██████╔╝███████╗███████║",
        "           ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝",
    ]
    for row in art:
        center(row, Fore.CYAN, True)


def section(title):
    print()
    print(f"{ACCENT}╭{'─' * (UI_WIDTH - 2)}╮{Style.RESET_ALL}")
    print(f"{ACCENT}│{Style.RESET_ALL} {TITLE}{title:<{UI_WIDTH - 4}}{Style.RESET_ALL} {ACCENT}│{Style.RESET_ALL}")
    print(f"{ACCENT}╰{'─' * (UI_WIDTH - 2)}╯{Style.RESET_ALL}")


def footer():
    print()
    line("─", UI_WIDTH, Fore.LIGHTBLACK_EX)
    center(f"{APP_CREDIT}  •  {APP_NAME} {APP_VERSION}", Fore.LIGHTBLACK_EX)
    line("─", UI_WIDTH, Fore.LIGHTBLACK_EX)


def pause():
    print()
    input(f"{MUTED}Press {Fore.WHITE}[ENTER]{MUTED} to continue...{Style.RESET_ALL}")


def banner():
    clear_screen()
    print()
    print(f"{ACCENT_2}╭{'═' * (UI_WIDTH - 2)}╮{Style.RESET_ALL}")
    _big_weird_tools()
    print(f"{ACCENT_2}├{'═' * (UI_WIDTH - 2)}┤{Style.RESET_ALL}")
    center("WEIRDMARKET  •  OFFICIAL TOOLS", Fore.MAGENTA, True)
    center("VALID / BAN CHECKER", Fore.CYAN, True)
    center(APP_VERSION, Fore.LIGHTBLACK_EX)
    print(f"{ACCENT_2}╰{'═' * (UI_WIDTH - 2)}╯{Style.RESET_ALL}")

# ── VALID MODE ────────────────────────────────────────────────────────

def valid_single():
    banner()
    section("◈  CEK VALID • SINGLE")
    device_id = input(
        f"\n  {Fore.MAGENTA}WEIRD{Style.RESET_ALL} "
        f"{Fore.CYAN}❯{Style.RESET_ALL} DEVICE ID\n"
        f"  {Fore.YELLOW}➤ {Style.RESET_ALL}"
    ).strip()

    if not device_id:
        print(f"\n  {Fore.RED}✖ ERROR: No Device ID entered.{Style.RESET_ALL}")
        pause()
        return

    print(f"\n  {Fore.MAGENTA}◌{Style.RESET_ALL} Checking valid status...")
    bot = GameLogin(device_id)
    acc_id, zone_id = bot.run()

    if acc_id and zone_id:
        save_valid_result(device_id, acc_id, zone_id)
    else:
        print(f"\n  {Fore.RED}✖ LOGIN / VALIDATION FAILED{Style.RESET_ALL}")

    footer()
    pause()

def save_valid_result(device_id, account_id, zone_id):
    result_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "VALID_RESULTS.txt")
    with open(result_file, "a", encoding="utf-8") as f:
        f.write(
            f"DEVICE ID  : {device_id}\n"
            f"ACCOUNT ID : {account_id}\n"
            f"ZONE ID    : {zone_id}\n"
            f"{'-' * 58}\n"
        )

    # ── PREMIUM VALID HIT CARD ─────────────────────────────────────────
    # Compact, consistent palette: green = success, cyan = data, grey = meta.
    width = UI_WIDTH
    inner = width - 2
    device_display = device_id if len(device_id) <= inner - 14 else device_id[:inner - 17] + "..."

    print()
    print(f"{Fore.GREEN}╭{'━' * inner}╮{Style.RESET_ALL}")
    print(f"{Fore.GREEN}│{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}{'✓  VALID HIT'.center(inner)}{Style.RESET_ALL}{Fore.GREEN}│{Style.RESET_ALL}")
    print(f"{Fore.GREEN}├{'─' * inner}┤{Style.RESET_ALL}")
    print(f"{Fore.GREEN}│{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}DEVICE ID{Style.RESET_ALL}  {Fore.WHITE}{device_display}{Style.RESET_ALL}" + ' ' * max(0, inner - 12 - len(device_display)) + f"{Fore.GREEN}│{Style.RESET_ALL}")
    print(f"{Fore.GREEN}│{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}ACCOUNT ID{Style.RESET_ALL} {Fore.CYAN}{Style.BRIGHT}{account_id}{Style.RESET_ALL}" + ' ' * max(0, inner - 13 - len(str(account_id))) + f"{Fore.GREEN}│{Style.RESET_ALL}")
    print(f"{Fore.GREEN}│{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}ZONE ID{Style.RESET_ALL}    {Fore.CYAN}{Style.BRIGHT}{zone_id}{Style.RESET_ALL}" + ' ' * max(0, inner - 13 - len(str(zone_id))) + f"{Fore.GREEN}│{Style.RESET_ALL}")
    print(f"{Fore.GREEN}├{'─' * inner}┤{Style.RESET_ALL}")
    saved = "✓  SAVED  •  VALID_RESULTS.txt"
    print(f"{Fore.GREEN}│{Style.RESET_ALL}{Fore.YELLOW}{saved.center(inner)}{Style.RESET_ALL}{Fore.GREEN}│{Style.RESET_ALL}")
    print(f"{Fore.GREEN}╰{'━' * inner}╯{Style.RESET_ALL}")

def valid_bulk():
    banner()
    section("◈  CEK VALID • BULK")
    filepath = input(
        f"\n  {Fore.CYAN}FILE PATH{Style.RESET_ALL}\n  "
        f"{Fore.YELLOW}➤ {Style.RESET_ALL}"
    ).strip().replace('"', '')

    if not os.path.exists(filepath):
        print(f"\n  {Fore.RED}✖ File not found.{Style.RESET_ALL}")
        pause()
        return

    with open(filepath, "r", encoding="utf-8") as f:
        device_ids = read_device_ids_from_file(filepath)

    if not device_ids:
        print(f"\n  {Fore.RED}✖ File is empty.{Style.RESET_ALL}")
        pause()
        return

    valid_count = 0
    fail_count = 0
    total = len(device_ids)

    print()
    for i, dev_id in enumerate(device_ids, 1):
        print(f"  {Fore.CYAN}[{i:>4}/{total:<4}]{Style.RESET_ALL} {dev_id[:52]}")
        try:
            bot = GameLogin(dev_id)
            acc_id, zone_id = bot.run()
            if acc_id and zone_id:
                valid_count += 1
                save_valid_result(dev_id, acc_id, zone_id)
                print(f"     {Fore.GREEN}✓ VALID{Style.RESET_ALL}")
            else:
                fail_count += 1
                print(f"     {Fore.RED}✖ FAILED{Style.RESET_ALL}")
        except Exception as e:
            fail_count += 1
            print(f"     {Fore.RED}✖ ERROR: {e}{Style.RESET_ALL}")

    section("◈  VALID BULK COMPLETE")
    print(f"\n  {Fore.GREEN}✓ VALID  : {valid_count}{Style.RESET_ALL}")
    print(f"  {Fore.RED}✖ FAILED : {fail_count}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}◉ TOTAL  : {total}{Style.RESET_ALL}")
    footer()
    pause()

# ── BAN MODE ──────────────────────────────────────────────────────────
# ── SILENT BULK CHECKER FLOW ──────────────────────────────────────────
def format_ban_string(device_id: str, ban_info: dict) -> str:
    reason = ban_info.get('reason_name', 'Using Plug-in Apps to Compromise Competitive Fairness')
    day = ban_info.get('endtime_day')
    hour = ban_info.get('endtime_hour', '00')
    minute = ban_info.get('endtime_min', '00')
    sec = ban_info.get('endtime_sec', '00')
    return f"{device_id} |  Reason Name: {reason} |  Duration: Day {day}, {hour}:{minute}:{sec}"

def check_device_ban_silent(device_id: str) -> Tuple[str, str]:
    conn = BanCheckerConnection(device_id)
    try:
        conn.connect('login.ml.youngjoygame.com', 30021)
        conn.send_data(1, SdpStruct({
            0: conn.device_id,
            1: f'gps_adid={conn.advertising_id}&android_id={conn.android_id}&device_unique_id={conn.imei_md5}',
            2: conn.client_version,
            3: conn.channel,
            4: 'en'
        }))

        pkt_id, res = conn.recv_data()
        banned, ban_info = inspect_for_ban(pkt_id, res)
        if banned: return "BANNED", format_ban_string(device_id, ban_info)

        if pkt_id == 2 and res:
            conn.account_id = res.get(0)
            conn.session_key = res.get(1)
            zone_data = res.get(2)
            if isinstance(zone_data, dict): conn.zone_id = zone_data.get(0, 0)
            elif isinstance(zone_data, list) and len(zone_data) > 0:
                conn.zone_id = zone_data[0] if not isinstance(zone_data[0], dict) else zone_data[0].get(0, 0)
            else: conn.zone_id = zone_data or 0
        else:
            return "UNKNOWN", device_id

        conn.send_data(5, SdpStruct({
            0: conn.account_id, 1: conn.session_key, 2: conn.client_version,
            5: conn.zone_id, 6: conn.channel
        }))

        pkt_id, res = conn.recv_data()
        banned, ban_info = inspect_for_ban(pkt_id, res)
        if banned: return "BANNED", format_ban_string(device_id, ban_info)

        if pkt_id == 6 and res:
            game_server = res[1]
            conn.game_server_host, conn.game_server_port = game_server.split(':')
            conn.game_server_port = int(conn.game_server_port)
        else:
            return "UNKNOWN", device_id

        conn.cleanup()
        conn.connect(conn.game_server_host, conn.game_server_port)

        conn.send_data(10001, SdpStruct({
            0: conn.account_id, 1: conn.session_key, 2: conn.zone_id,
            4: conn.client_version, 13: conn.channel, 15: conn.device_id
        }))
        conn.send_data(10101, SdpStruct({0: 0, 2: 2}))

        role_requested = False
        while True:
            pkt_id, res = conn.recv_data()
            banned, ban_info = inspect_for_ban(pkt_id, res)
            
            if banned:
                return "BANNED", format_ban_string(device_id, ban_info)

            if pkt_id is None or pkt_id == -1:
                return "UNKNOWN", device_id
            elif pkt_id == 10002 and not role_requested:
                conn.send_data(10003, SdpStruct({
                    0: conn.account_id, 1: conn.session_key, 2: conn.zone_id,
                    3: conn.client_version, 4: conn.channel, 5: conn.device_id
                }))
                role_requested = True
            elif pkt_id in (10004, 10008):
                return "CLEAN", device_id
    except Exception:
        return "UNKNOWN", device_id
    finally:
        conn.cleanup()

# ── THREADING & BULK LOGIC ──────────────────────────────────────────
progress_lock = threading.Lock()
file_lock = threading.Lock()
processed_count = 0
banned_count = 0
clean_count = 0
total_count = 0

def update_progress():
    """Render a compact single-line progress dashboard.

    Deliberately avoids cursor-up / multi-line ANSI positioning.  This keeps
    the UI stable on Termux, where wrapped ANSI output can create the broken
    split-column appearance seen in earlier versions.
    """
    global processed_count, banned_count, clean_count, total_count
    with progress_lock:
        total = max(total_count, 1)
        done = min(processed_count, total_count)
        pct = (done / total) * 100

        # Keep the entire dashboard comfortably inside a phone terminal.
        bar_width = 18
        filled = int(bar_width * done / total)
        bar = "━" * filled + "─" * (bar_width - filled)

        border = Fore.LIGHTBLACK_EX
        title = Fore.CYAN + Style.BRIGHT
        accent = Fore.CYAN + Style.BRIGHT
        neutral = Fore.WHITE + Style.BRIGHT
        muted = Fore.LIGHTBLACK_EX
        warning = Fore.YELLOW + Style.BRIGHT
        danger = Fore.RED + Style.BRIGHT

        # One physical terminal line: no cursor movement, no clearing rows.
        dashboard = (
            f"{border}│{Style.RESET_ALL} "
            f"{title}WEIRD TOOLS{Style.RESET_ALL} "
            f"{muted}• BULK CHECK{Style.RESET_ALL} "
            f"{neutral}{done}/{total_count}{Style.RESET_ALL} "
            f"{accent}{bar}{Style.RESET_ALL} "
            f"{warning}{pct:5.1f}%{Style.RESET_ALL} "
            f"{muted}│{Style.RESET_ALL} "
            f"{neutral}CHECKED {done}{Style.RESET_ALL} "
            f"{muted}│{Style.RESET_ALL} "
            f"{accent}NOT BAN {clean_count}{Style.RESET_ALL} "
            f"{muted}│{Style.RESET_ALL} "
            f"{danger}BAN {banned_count}{Style.RESET_ALL}"
        )
        print("\r\033[2K" + dashboard, end="", flush=True)

def process_device_worker(device_id: str, ban_filepath: str, clean_filepath: str):
    global processed_count, banned_count, clean_count
    
    status, result_str = check_device_ban_silent(device_id)
    
    with file_lock:
        if status == "BANNED":
            banned_count += 1
            with open(ban_filepath, "a", encoding="utf-8") as f:
                f.write(result_str + "\n")
        elif status == "CLEAN":
            clean_count += 1
            with open(clean_filepath, "a", encoding="utf-8") as f:
                f.write(result_str + "\n")
        elif status == "UNKNOWN":
            with open(os.path.join(os.path.dirname(ban_filepath), "UNKNOWN.txt"), "a", encoding="utf-8") as f:
                f.write(result_str + "\n")
        
        processed_count += 1
    
    update_progress()

def run_bulk_mode():
    global processed_count, banned_count, clean_count, total_count
    processed_count = 0
    banned_count = 0
    clean_count = 0
    
    print(f"\n{Fore.YELLOW}--- BULK CHECK MODE ---{Style.RESET_ALL}")
    
    filepath = input(f"{Fore.CYAN}Enter filepath containing Device IDs: {Style.RESET_ALL}").strip()
    if not os.path.exists(filepath):
        print(f"{Fore.RED}File not found!{Style.RESET_ALL}")
        return

    try:
        threads_input = int(input(f"{Fore.CYAN}Enter number of threads (1-20 max): {Style.RESET_ALL}").strip())
        threads = max(1, min(20, threads_input))
    except ValueError:
        threads = 1
        print(f"{Fore.YELLOW}Invalid input, defaulting to 1 thread.{Style.RESET_ALL}")

    with open(filepath, "r", encoding="utf-8") as f:
        device_ids = [line.strip() for line in f if line.strip()]
    
    total_count = len(device_ids)
    if total_count == 0:
        print(f"{Fore.RED}No valid Device IDs found in file.{Style.RESET_ALL}")
        return

    # Target Directory setup
    # Termux/Android: save bulk results beside this script.
    base_dir = os.path.dirname(os.path.abspath(__file__))
    save_dir = os.path.join(base_dir, "ban_results")
    os.makedirs(save_dir, exist_ok=True)
    ban_file = os.path.join(save_dir, "BAN 100%.txt")
    clean_file = os.path.join(save_dir, "NOT BAN 100%.txt")

    print(f"{Fore.CYAN}╭────────────────────────────────────────────────────────────────────╮{Style.RESET_ALL}")
    print(f"{Fore.CYAN}│{Style.RESET_ALL} {Fore.YELLOW}⚡ BULK CHECK INITIALIZED{Style.RESET_ALL}   "
          f"{Fore.LIGHTBLACK_EX}Threads:{Style.RESET_ALL} {Fore.WHITE}{threads}{Style.RESET_ALL}"
          f" {Fore.CYAN}│{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╰────────────────────────────────────────────────────────────────────╯{Style.RESET_ALL}\n")
    update_progress()

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(process_device_worker, d_id, ban_file, clean_file) 
            for d_id in device_ids
        ]
        # Retrieve every future result so unexpected worker errors are not hidden.
        for future in futures:
            try:
                future.result()
            except Exception as e:
                print(f"\\n{Fore.RED}Worker error: {type(e).__name__}: {e}{Style.RESET_ALL}")

    print(f"\n{Fore.LIGHTBLACK_EX}╭────────────────────────────────────────────────────────────────────╮{Style.RESET_ALL}")
    print(f"{Fore.LIGHTBLACK_EX}│{Style.RESET_ALL} {Fore.WHITE}{Style.BRIGHT}BULK CHECK COMPLETE{Style.RESET_ALL}"
          f" {Fore.LIGHTBLACK_EX}│{Style.RESET_ALL}")
    print(f"{Fore.LIGHTBLACK_EX}╰────────────────────────────────────────────────────────────────────╯{Style.RESET_ALL}")
    unknown_file = os.path.join(save_dir, "UNKNOWN.txt")
    print(
        f"Results saved to:\n"
        f"- {ban_file}\n"
        f"- {clean_file}\n"
        f"- {unknown_file}\n"
    )
    print(
        f"{Fore.WHITE}Summary: {Fore.GREEN}{clean_count} NOT BAN"
        f"{Fore.WHITE} | {Fore.RED}{banned_count} BAN"
        f"{Fore.WHITE} | {Fore.YELLOW}{total_count - clean_count - banned_count} UNKNOWN/ERROR"
        f"{Style.RESET_ALL}"
    )



# Simpan nama fungsi bulk ban yang sudah ada dari file asli.
def check_device_ban(device_id: str):
    """UI wrapper for the existing silent ban checker."""
    print(f"\n  {Fore.MAGENTA}◌{Style.RESET_ALL} Checking ban status...")
    status, result = check_device_ban_silent(device_id)

    if status == "BANNED":
        print(f"\n  {Fore.RED}{Style.BRIGHT}✖ BANNED{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}{result}{Style.RESET_ALL}")
    elif status == "CLEAN":
        print(f"\n  {Fore.GREEN}{Style.BRIGHT}✓ NOT BANNED{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}{result}{Style.RESET_ALL}")
    else:
        print(f"\n  {Fore.YELLOW}{Style.BRIGHT}⚠ UNKNOWN / CHECK FAILED{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}{result}{Style.RESET_ALL}")

    return status, result


def ban_single():
    banner()
    section("◈  CEK BAN • SINGLE")
    device_id = input(
        f"\n  {Fore.CYAN}DEVICE ID{Style.RESET_ALL}\n  "
        f"{Fore.YELLOW}➤ {Style.RESET_ALL}"
    ).strip()

    if not device_id:
        print(f"\n  {Fore.RED}✖ No Device ID entered.{Style.RESET_ALL}")
        pause()
        return

    check_device_ban(device_id)
    pause()

# ── MENU SUB-FITUR ───────────────────────────────────────────────────
def valid_menu():
    while True:
        banner()
        section("CEK VALID")
        print(
            f"\n  {Fore.CYAN}[1]{Style.RESET_ALL}  SINGLE CHECK\n"
            f"  {Fore.CYAN}[2]{Style.RESET_ALL}  BULK CHECK\n"
            f"  {Fore.LIGHTBLACK_EX}[0]{Style.RESET_ALL}  BACK"
        )
        choice = input(f"\n{Fore.CYAN}Pilih menu [0-2]: {Style.RESET_ALL}").strip()

        if choice == "1":
            valid_single()
        elif choice == "2":
            valid_bulk()
        elif choice == "0":
            return
        else:
            print(f"{Fore.RED}Pilihan tidak valid.{Style.RESET_ALL}")
            pause()

def ban_menu():
    while True:
        banner()
        section("CEK BAN")
        print(
            f"\n  {Fore.CYAN}[1]{Style.RESET_ALL}  SINGLE CHECK\n"
            f"  {Fore.CYAN}[2]{Style.RESET_ALL}  BULK CHECK\n"
            f"  {Fore.LIGHTBLACK_EX}[0]{Style.RESET_ALL}  BACK"
        )
        choice = input(f"\n{Fore.CYAN}Pilih menu [0-2]: {Style.RESET_ALL}").strip()

        if choice == "1":
            ban_single()
        elif choice == "2":
            run_bulk_mode()
            pause()
        elif choice == "0":
            return
        else:
            print(f"{Fore.RED}Pilihan tidak valid.{Style.RESET_ALL}")
            pause()

def normalize(line: str) -> str:
    """
    Ambil device ID dari satu baris, termasuk jika ID diawali nomor/list.

    Contoh:
      and_xxx
      ios_xxx
      1. and_xxx
      1) and_xxx
      - and_xxx
      and_xxx | info
      and_xxx:info
    """
    raw = (line or "").strip()
    if not raw:
        return ""

    match = re.search(r"(?i)(?:and_|ios_)[A-Za-z0-9_-]+", raw)
    if not match:
        return ""

    candidate = match.group(0)
    return candidate if DEVICE_RE.fullmatch(candidate) else ""


def extract_records(text: str):
    """
    Ekstrak record Device ID dengan dua format:
    1) Record dipisahkan oleh garis --- (full-info).
    2) Banyak Device ID ditulis satu per baris tanpa separator.

    Jika sebuah blok tanpa separator memiliki beberapa Device ID, setiap
    baris Device ID dianggap sebagai awal record baru sehingga tidak hanya
    ID pertama yang terbaca.
    """
    text = text or ""
    blocks = re.split(r"(?m)^\s*---\s*$", text)
    records = []
    id_pattern = re.compile(r"(?i)(?:and_|ios_)[A-Za-z0-9_-]+")

    for block in blocks:
        block = block.strip()
        if not block:
            continue

        lines = block.splitlines()
        id_lines = []
        for idx, line in enumerate(lines):
            m = id_pattern.search(line)
            if m and DEVICE_RE.fullmatch(m.group(0)):
                id_lines.append((idx, m.group(0)))

        if not id_lines:
            continue

        # Tanpa separator dan ada >1 ID: pecah berdasarkan baris ID.
        # Ini menangani file seperti:
        # and_xxx
        # and_yyy
        # ios_zzz
        if len(id_lines) > 1:
            for n, (start_idx, device_id) in enumerate(id_lines):
                end_idx = id_lines[n + 1][0] if n + 1 < len(id_lines) else len(lines)
                chunk = lines[start_idx:end_idx]
                cleaned = []
                for line in chunk:
                    line = line.rstrip()
                    if not line.strip():
                        cleaned.append("")
                        continue
                    m = id_pattern.search(line)
                    if m and m.group(0).lower() == device_id.lower():
                        prefix = line[:m.start()]
                        if re.fullmatch(r"\s*(?:\d+[.)]\s*|[-*]\s*)?", prefix):
                            line = line[m.start():]
                    cleaned.append(line)
                record_text = "\n".join(cleaned).strip()
                if record_text:
                    records.append({"id": device_id, "text": record_text})
            continue

        # Format full-info dengan satu ID dalam blok.
        start_idx, device_id = id_lines[0]
        cleaned = []
        for line in lines[start_idx:]:
            line = line.rstrip()
            if not line.strip():
                cleaned.append("")
                continue
            m = id_pattern.search(line)
            if m and m.group(0).lower() == device_id.lower():
                prefix = line[:m.start()]
                if re.fullmatch(r"\s*(?:\d+[.)]\s*|[-*]\s*)?", prefix):
                    line = line[m.start():]
            cleaned.append(line)

        record_text = "\n".join(cleaned).strip()
        if record_text:
            records.append({"id": device_id, "text": record_text})

    return records


def load_records(path: str):
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(path)

    with p.open("r", encoding="utf-8-sig", errors="ignore") as f:
        return extract_records(f.read())


def load_file(path: str):
    """Kompatibilitas: kembalikan daftar ID dari record."""
    return [r["id"] for r in load_records(path)]


def unique_records_keep_order(records):
    seen = set()
    out = []
    duplicates = 0

    for record in records:
        key = record["id"].lower()
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        out.append(record)

    return out, duplicates


def unique_keep_order(items):
    seen = set()
    out = []
    duplicates = 0

    for item in items:
        key = item.lower()
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        out.append(item)

    return out, duplicates


def stats(items):
    android = [x for x in items if x.lower().startswith("and_")]
    ios = [x for x in items if x.lower().startswith("ios_")]

    t = Table(title="Statistics", expand=False)
    t.add_column("Category")
    t.add_column("Count", justify="right")
    t.add_row("Total", str(len(items)))
    t.add_row("Android / and_", str(len(android)))
    t.add_row("iOS / ios_", str(len(ios)))
    console.print(t)


def save_numbered_records(path: Path, records):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        for i, record in enumerate(records, 1):
            # Nomor hanya ditambahkan ke ID pertama setiap record.
            lines = record["text"].splitlines()
            if lines:
                f.write(f"{i}. {lines[0]}\n")
                for line in lines[1:]:
                    f.write(line + "\n")
            f.write("---\n")


def save_plain_records(path: Path, records):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(record["text"].rstrip() + "\n")
            f.write("---\n")


# ── FILTER HELPERS (OFFLINE / LOCAL FULL-INFO SPLIT) ────────────────
def _first_int(text, patterns):
    for pattern in patterns:
        m = re.search(pattern, text or "", re.I | re.M)
        if m:
            try:
                return int(m.group(1).replace(",", "").strip())
            except (ValueError, TypeError):
                pass
    return None


def get_skin_count(record):
    text = record.get("text", "")
    return _first_int(text, [
        r"^\s*(?:skin(?:s)?|skin_count|skin count|jumlah skin)\s*[:=\-]\s*(\d+)",
        r"(?:skin(?:s)?|skin_count|skin count|jumlah skin)\s*[:=]\s*(\d+)",
    ])


def get_level(record):
    text = record.get("text", "")
    return _first_int(text, [
        r"^\s*(?:level|lvl)\s*[:=\-]\s*(\d+)",
        r"(?:level|lvl)\s*[:=]\s*(\d+)",
    ])


def get_rank(record):
    text = record.get("text", "")
    ranks = ("grandmaster", "mythic", "legend", "epic", "master", "elite", "warrior")
    for rank in ranks:
        if re.search(rf"(?:^|[\\s:=\\-]){re.escape(rank)}(?:$|[\\s,._\\-])", text, re.I | re.M):
            return rank
    return None


COLLECTOR_TIERS = (
    "Amateur Collector",
    "Junior Collector",
    "Seasoned Collector",
    "Expert Collector",
    "Renowned Collector",
    "Exalted Collector",
    "Mega Collector",
    "World Collector",
    "Supreme Collector",
)


def get_collector(record):
    """Return the collector tier found in the local full-info record."""
    text = record.get("text", "")
    for tier in reversed(COLLECTOR_TIERS):
        if re.search(rf"\b{re.escape(tier)}\b", text, re.I):
            return tier
    return None


def filter_records_with_collector(records, collector=None, skin_min=None, level_min=None, ranks=None):
    """Filter local full-info records, optionally by collector tier."""
    out = filter_records(records, skin_min=skin_min, level_min=level_min, ranks=ranks)
    if collector is None:
        return out
    allowed = {x.lower() for x in collector} if isinstance(collector, (list, tuple, set)) else {str(collector).lower()}
    return [r for r in out if (get_collector(r) or "").lower() in allowed]


def filter_records(records, skin_min=None, level_min=None, ranks=None):
    """Filter full-info records using local text only."""
    ranks = {r.lower() for r in (ranks or [])}
    out = []
    for record in records:
        if skin_min is not None:
            value = get_skin_count(record)
            if value is None or value < skin_min:
                continue
        if level_min is not None:
            value = get_level(record)
            if value is None or value < level_min:
                continue
        if ranks:
            value = get_rank(record)
            if value is None or value.lower() not in ranks:
                continue
        out.append(record)
    return out


def _filter_split_chunks(records, out_dir, prefix, size):
    parts = 0
    for start in range(0, len(records), size):
        parts += 1
        save_numbered_records(out_dir / f"{prefix}_{parts:03d}.txt", records[start:start + size])
    return parts


def split_filter_menu(records, out_dir, size):
    """Interactive local filter for FULL INFO records."""
    while True:
        print(
            f"\n{Fore.CYAN}FILTER SPLIT{Style.RESET_ALL}"
            f"\n  {Fore.CYAN}[1]{Style.RESET_ALL} Skin 50+ / 100+ / 200+ / 300+"
            f"\n  {Fore.CYAN}[2]{Style.RESET_ALL} Level 50+ / 75+ / 100+"
            f"\n  {Fore.CYAN}[3]{Style.RESET_ALL} Rank Warrior / Elite / Master / Grandmaster / Epic / Legend / Mythic"
            f"\n  {Fore.CYAN}[4]{Style.RESET_ALL} Kombinasi Skin + Level + Rank"
            f"\n  {Fore.CYAN}[5]{Style.RESET_ALL} Collector Tier"
            f"\n  {Fore.LIGHTBLACK_EX}[0]{Style.RESET_ALL} Kembali"
        )
        choice = input(f"\n{Fore.CYAN}Pilih [0-5]: {Style.RESET_ALL}").strip()
        if choice == "0":
            return

        skin_min = None
        level_min = None
        ranks = []
        collectors = []
        prefix = "filtered"

        if choice == "1":
            try:
                skin_min = int(input("Skin minimum [50/100/200/300]: ").strip())
            except ValueError:
                print(f"{Fore.RED}Nilai skin tidak valid.{Style.RESET_ALL}")
                continue
            if skin_min not in (50, 100, 200, 300):
                print(f"{Fore.YELLOW}Gunakan 50, 100, 200, atau 300.{Style.RESET_ALL}")
                continue
            prefix = f"skin_{skin_min}plus"

        elif choice == "2":
            try:
                level_min = int(input("Level minimum [50/75/100]: ").strip())
            except ValueError:
                print(f"{Fore.RED}Nilai level tidak valid.{Style.RESET_ALL}")
                continue
            if level_min not in (50, 75, 100):
                print(f"{Fore.YELLOW}Gunakan 50, 75, atau 100.{Style.RESET_ALL}")
                continue
            prefix = f"level_{level_min}plus"

        elif choice == "3":
            rank_map = {
                "1": "warrior", "2": "elite", "3": "master",
                "4": "grandmaster", "5": "epic", "6": "legend", "7": "mythic"
            }
            print("  [1] Warrior  [2] Elite  [3] Master  [4] Grandmaster")
            print("  [5] Epic     [6] Legend [7] Mythic")
            selected = input("Pilih rank (contoh: 1,3,7): ").replace(" ", "").split(",")
            ranks = [rank_map[x] for x in selected if x in rank_map]
            if not ranks:
                print(f"{Fore.RED}Rank tidak dipilih.{Style.RESET_ALL}")
                continue
            prefix = "rank_" + "_".join(ranks)

        elif choice == "5":
            print("\nCollector Tier:")
            for i, tier in enumerate(COLLECTOR_TIERS, 1):
                print(f"  [{i}] {tier}")
            selected = input("Pilih collector (contoh: 1,4,9): ").replace(" ", "").split(",")
            collectors = [COLLECTOR_TIERS[int(x) - 1] for x in selected if x.isdigit() and 1 <= int(x) <= len(COLLECTOR_TIERS)]
            if not collectors:
                print(f"{Fore.RED}Collector tidak dipilih.{Style.RESET_ALL}")
                continue
            prefix = "collector_" + "_".join(x.lower().replace(" ", "_") for x in collectors)

        elif choice == "4":
            raw = input("Skin minimum [kosong=semua]: ").strip()
            if raw:
                try:
                    skin_min = int(raw)
                except ValueError:
                    print(f"{Fore.RED}Nilai skin tidak valid.{Style.RESET_ALL}")
                    continue
            raw = input("Level minimum [kosong=semua]: ").strip()
            if raw:
                try:
                    level_min = int(raw)
                except ValueError:
                    print(f"{Fore.RED}Nilai level tidak valid.{Style.RESET_ALL}")
                    continue
            raw = input("Rank [kosong=semua, pisahkan koma]: ").strip()
            if raw:
                allowed = {"warrior", "elite", "master", "grandmaster", "epic", "legend", "mythic"}
                ranks = [x.strip().lower() for x in raw.split(",") if x.strip().lower() in allowed]
            prefix = "combined_filter"
        else:
            print(f"{Fore.RED}Pilihan tidak valid.{Style.RESET_ALL}")
            continue

        matched = filter_records_with_collector(
            records, collector=collectors, skin_min=skin_min, level_min=level_min, ranks=ranks
        )
        if not matched:
            print(f"\n{Fore.YELLOW}Tidak ada record yang cocok.{Style.RESET_ALL}")
            continue

        # Bersihkan hasil lama untuk prefix yang sama.
        for old in out_dir.glob(f"{prefix}_*.txt"):
            old.unlink()
        parts = _filter_split_chunks(matched, out_dir, prefix, size)
        print(
            f"\n{Fore.GREEN}✓ {len(matched)} record cocok{Style.RESET_ALL}"
            f"\n{Fore.GREEN}✓ {parts} file dibuat di {out_dir}{Style.RESET_ALL}"
        )
        pause()


def export_all_records(records):
    RESULTS.mkdir(exist_ok=True)

    android = [r for r in records if r["id"].lower().startswith("and_")]
    ios = [r for r in records if r["id"].lower().startswith("ios_")]

    save_numbered_records(RESULTS / "all_devices.txt", records)
    save_numbered_records(RESULTS / "android_and.txt", android)
    save_numbered_records(RESULTS / "ios.txt", ios)

    console.print("[green]✓[/green] results/all_devices.txt")
    console.print("[green]✓[/green] results/android_and.txt")
    console.print("[green]✓[/green] results/ios.txt")


def split_record_files(records, size=50):
    RESULTS.mkdir(exist_ok=True)
    split_dir = RESULTS / "parts"
    split_dir.mkdir(exist_ok=True)

    # Hapus part lama supaya hasil tidak tercampur.
    for old in split_dir.glob("part_*.txt"):
        old.unlink()

    total_parts = 0
    for start in range(0, len(records), size):
        total_parts += 1
        chunk = records[start:start + size]
        # SETIAP record dibawa utuh, termasuk seluruh info/statistiknya.
        save_numbered_records(
            split_dir / f"part_{total_parts:03d}.txt",
            chunk
        )

    console.print(
        f"[green]✓[/green] {len(records)} record dibagi menjadi "
        f"{total_parts} file di {split_dir}/"
    )


def process_file():
    path = Prompt.ask("Path file TXT").strip().strip("\"'")

    try:
        records = load_records(path)
    except Exception as e:
        console.print(f"[red]Gagal membaca file:[/red] {e}")
        return

    clean, duplicates = unique_records_keep_order(records)

    console.print()
    console.print(f"Record/device ID ditemukan : [cyan]{len(records)}[/cyan]")
    console.print(f"Duplikat dihapus           : [yellow]{duplicates}[/yellow]")
    console.print(f"Record unik                : [green]{len(clean)}[/green]")

    android = [r for r in clean if r["id"].lower().startswith("and_")]
    ios = [r for r in clean if r["id"].lower().startswith("ios_")]

    t = Table(title="Statistics", expand=False)
    t.add_column("Category")
    t.add_column("Count", justify="right")
    t.add_row("Total", str(len(clean)))
    t.add_row("Android / and_", str(len(android)))
    t.add_row("iOS / ios_", str(len(ios)))
    console.print(t)

    # Export dan split SEKALIGUS membawa seluruh info tiap record.
    export_all_records(clean)

    size = IntPrompt.ask("Jumlah ID per file split", default=50)
    if size <= 0:
        console.print("[yellow]Ukuran split tidak valid, memakai 50.[/yellow]")
        size = 50

    split_record_files(clean, size)

    console.print(
        "\\n[bold green]Selesai.[/bold green] "
        "Info/statistik setiap ID ikut tersimpan di file split."
    )
    input("\\nTekan Enter untuk kembali...")


def separate_manual():
    path = Prompt.ask("Path file TXT").strip().strip("\"'")

    try:
        records = load_records(path)
    except Exception as e:
        console.print(f"[red]Gagal membaca file:[/red] {e}")
        return

    clean, duplicates = unique_records_keep_order(records)
    android = [r for r in clean if r["id"].lower().startswith("and_")]
    ios = [r for r in clean if r["id"].lower().startswith("ios_")]

    RESULTS.mkdir(exist_ok=True)
    save_numbered_records(RESULTS / "android_and.txt", android)
    save_numbered_records(RESULTS / "ios.txt", ios)

    console.print(
        f"\\n[green]Android:[/green] {len(android)} ID"
        f"\\n[green]iOS:[/green] {len(ios)} ID"
        f"\\n[yellow]Duplikat dihapus:[/yellow] {duplicates}"
    )
    console.print(
        "[dim]Seluruh info/statistik masing-masing ID ikut tersimpan "
        "di android_and.txt dan ios.txt[/dim]"
    )
    input("\\nTekan Enter untuk kembali...")

# ── SPLIT / DEVICE MANAGER ────────────────────────────────────────────
def split_manager_menu():
    while True:
        banner()
        section("◈  SPLIT / DEVICE MANAGER")
        print(
            f"\n  {Fore.CYAN}[1]{Style.RESET_ALL}  SPLIT FULL INFO"
            f"\n  {Fore.CYAN}[2]{Style.RESET_ALL}  SPLIT DEVICE ID"
            f"\n  {Fore.CYAN}[3]{Style.RESET_ALL}  SPLIT DEVICE ID • ANDROID / iOS"
            f"\n  {Fore.CYAN}[4]{Style.RESET_ALL}  DEDUP + EXPORT FULL INFO"
            f"\n  {Fore.CYAN}[5]{Style.RESET_ALL}  SPLIT FILTER • SKIN / LEVEL / RANK / COLLECTOR"
            f"\n  {Fore.LIGHTBLACK_EX}[0]{Style.RESET_ALL}  BACK"
        )
        choice = input(f"\n{Fore.CYAN}Pilih menu [0-5]: {Style.RESET_ALL}").strip()

        if choice == "0":
            return

        if choice not in {"1", "2", "3", "4", "5"}:
            print(f"{Fore.RED}Pilihan tidak valid.{Style.RESET_ALL}")
            pause()
            continue

        filepath = input(
            f"\n{Fore.CYAN}FILE TXT{Style.RESET_ALL}\n"
            f"{Fore.YELLOW}➤ {Style.RESET_ALL}"
        ).strip().strip('"').strip("'")

        try:
            records = load_records(filepath)
        except Exception as e:
            print(f"\n{Fore.RED}Gagal membaca file: {e}{Style.RESET_ALL}")
            pause()
            continue

        clean, duplicates = unique_records_keep_order(records)

        if not clean:
            print(f"\n{Fore.RED}Tidak ada Device ID valid (and_/ios_).{Style.RESET_ALL}")
            pause()
            continue

        try:
            size = int(input(
                f"{Fore.CYAN}Jumlah ID per file [default 50]: {Style.RESET_ALL}"
            ).strip() or "50")
        except ValueError:
            size = 50
        size = max(1, size)

        out_dir = RESULTS / "split"
        out_dir.mkdir(parents=True, exist_ok=True)

        # Bersihkan hasil split sebelumnya.
        for old in out_dir.glob("*.txt"):
            old.unlink()

        def write_chunks(items, prefix, full_info=False):
            total_parts = 0
            for start_i in range(0, len(items), size):
                total_parts += 1
                chunk = items[start_i:start_i + size]
                path = out_dir / f"{prefix}_{total_parts:03d}.txt"
                with path.open("w", encoding="utf-8") as f:
                    for idx, item in enumerate(chunk, start=1):
                        if full_info:
                            lines = item["text"].splitlines()
                            if lines:
                                f.write(f"{idx}. {lines[0]}\n")
                                for line in lines[1:]:
                                    f.write(line + "\n")
                            f.write("---\n")
                        else:
                            f.write(item + "\n")
            return total_parts

        if choice == "1":
            parts = write_chunks(clean, "full_info", full_info=True)
            print(f"\n{Fore.GREEN}✓ Split FULL INFO selesai: {parts} file{Style.RESET_ALL}")

        elif choice == "2":
            ids = [r["id"] for r in clean]
            parts = write_chunks(ids, "device_id")
            print(f"\n{Fore.GREEN}✓ Split DEVICE ID selesai: {parts} file{Style.RESET_ALL}")

        elif choice == "3":
            ids_and = [r["id"] for r in clean if r["id"].lower().startswith("and_")]
            ids_ios = [r["id"] for r in clean if r["id"].lower().startswith("ios_")]
            parts_and = write_chunks(ids_and, "android_and")
            parts_ios = write_chunks(ids_ios, "ios")
            print(
                f"\n{Fore.GREEN}✓ Android: {len(ids_and)} ID / {parts_and} file"
                f"\n✓ iOS: {len(ids_ios)} ID / {parts_ios} file"
                f"\n✓ Output: {out_dir}{Style.RESET_ALL}"
            )

        elif choice == "4":
            export_all_records(clean)
            print(
                f"\n{Fore.GREEN}✓ Export full info selesai"
                f"\n✓ Total unik: {len(clean)}"
                f"\n✓ Duplikat dihapus: {duplicates}{Style.RESET_ALL}"
            )

        elif choice == "5":
            split_filter_menu(clean, out_dir, size)

        pause()


# ── GABUNGAN BULK CHECKER DENGAN FULL INFO INPUT ─────────────────────
def read_device_ids_from_file(filepath):
    """Ambil hanya ID unik dari file biasa maupun file full-info."""
    records = load_records(filepath)
    clean, _ = unique_records_keep_order(records)
    return [r["id"] for r in clean]
def main_menu():
    while True:
        banner()
        section("MAIN MENU")
        print(
            f"\n  {Fore.YELLOW}{Style.BRIGHT}[1]{Style.RESET_ALL}  {TITLE}CEK VALID{Style.RESET_ALL}"
            f"   {MUTED}Single & Bulk Device ID validation{Style.RESET_ALL}\n"
            f"  {Fore.YELLOW}{Style.BRIGHT}[2]{Style.RESET_ALL}  {TITLE}CEK BAN{Style.RESET_ALL}"
            f"     {MUTED}Single & Bulk ban status checking{Style.RESET_ALL}\n"
            f"  {Fore.YELLOW}{Style.BRIGHT}[3]{Style.RESET_ALL}  {TITLE}SPLIT / DEVICE MANAGER{Style.RESET_ALL}"
            f" {MUTED}Full info, Device ID, Android & iOS{Style.RESET_ALL}\n"
            f"  {Fore.RED}{Style.BRIGHT}[0]{Style.RESET_ALL}  {TITLE}KELUAR{Style.RESET_ALL}"
        )
        footer()
        choice = input(
            f"\n{Fore.CYAN}{Style.BRIGHT}WEIRD TOOLS {Style.RESET_ALL}"
            f"{MUTED}› {Style.RESET_ALL}Pilih menu [0-3]: "
        ).strip()

        if choice == "1":
            valid_menu()
        elif choice == "2":
            ban_menu()
        elif choice == "3":
            split_manager_menu()
        elif choice == "0":
            clear_screen()
            print()
            print(f"{Fore.MAGENTA}╭{'═' * (UI_WIDTH - 2)}╮{Style.RESET_ALL}")
            center("WEIRD TOOLS", Fore.CYAN, True)
            center("Program selesai. Terima kasih.", Fore.LIGHTBLACK_EX)
            print(f"{Fore.MAGENTA}╰{'═' * (UI_WIDTH - 2)}╯{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}Pilihan tidak valid. Gunakan 0, 1, 2, atau 3.{Style.RESET_ALL}")
            pause()

if __name__ == "__main__":
    main_menu()
