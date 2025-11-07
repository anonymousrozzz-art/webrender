from flask import Flask, render_template, request, send_from_directory, session, flash, redirect, url_for, jsonify
import json
from pathlib import Path
import os
import copy
from datetime import datetime
import re
from groq import Groq

# Google Sheets (gspread + google oauth)
import gspread
from google.oauth2.service_account import Credentials

# Symmetric encryption (Fernet)
from cryptography.fernet import Fernet

# -------------------------
# Groq client (unchanged)
# -------------------------
GROQ_CLIENT = Groq(api_key=os.environ.get("GROQ_API_KEY"))

# -------------------------
# Config / Files (unchanged)
# -------------------------
PUBLIC_JSON = Path("all_profiles_public.json")
FULL_JSON = Path("all_profiles_full.json")
IMAGE_DIR = Path("static/images")
IGNORED_JSON = Path("ignored_profiles.json")  # local backup for deleted profiles

# -------------------------
# Flask app
# -------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_for_demo_only_change_me")

# -------------------------
# Google Sheets + Fernet config (Render-friendly)
# -------------------------
# Required environment variables:
# - GOOGLE_SA_JSON : The full service-account JSON content (as a single env var string)
# - GOOGLE_SHEET_ID : The spreadsheet id (from the sheet URL)
# - PASSWORD_ENC_KEY : base64 Fernet key (generate with Fernet.generate_key())
# Optional:
# - GOOGLE_SHEET_USERS_TAB (default "users")
# - GOOGLE_SHEET_ANALYTICS_TAB (default "analytics")
# - GOOGLE_SHEET_ANALYTICS_COMPACT_TAB (default "analytics_compact")
# - GOOGLE_SHEET_KEYWORD_TAB (default "keyword_searches")
# - GOOGLE_SHEET_PROFILE_TAB (default "profile_views")

GOOGLE_SA_JSON = os.environ.get("GOOGLE_SA_JSON")
GOOGLE_SHEET_ID = os.environ.get("GOOGLE_SHEET_ID")
USERS_SHEET_NAME = os.environ.get("GOOGLE_SHEET_USERS_TAB", "users")
ANALYTICS_SHEET_NAME = os.environ.get("GOOGLE_SHEET_ANALYTICS_TAB", "analytics")
ANALYTICS_COMPACT_SHEET_NAME = os.environ.get("GOOGLE_SHEET_ANALYTICS_COMPACT_TAB", "analytics_compact")
KEYWORD_SHEET_NAME = os.environ.get("GOOGLE_SHEET_KEYWORD_TAB", "keyword_searches")
PROFILE_SHEET_NAME = os.environ.get("GOOGLE_SHEET_PROFILE_TAB", "profile_views")
PASSWORD_ENC_KEY = os.environ.get("PASSWORD_ENC_KEY")  # fernet key (base64)

# Validate minimum config
if not GOOGLE_SA_JSON or not GOOGLE_SHEET_ID:
    print("WARNING: GOOGLE_SA_JSON and GOOGLE_SHEET_ID must be set to enable Google Sheets integration.")
    print("Users and analytics will not be persisted to Sheets until these are configured.")

if not PASSWORD_ENC_KEY:
    print("WARNING: PASSWORD_ENC_KEY is not set. Password encryption will be disabled until you set this env var.")
    # We still proceed, but encrypt/decrypt helpers will check and refuse if missing.

# Prepare Fernet
FERNET = None
if PASSWORD_ENC_KEY:
    try:
        FERNET = Fernet(PASSWORD_ENC_KEY.encode() if isinstance(PASSWORD_ENC_KEY, str) else PASSWORD_ENC_KEY)
    except Exception as e:
        print("Failed to initialize Fernet with PASSWORD_ENC_KEY:", e)
        FERNET = None

# -------------------------
# gspread client and sheet handle (initialized lazily)
# -------------------------
GS_CLIENT = None
GS_SHEET = None

def init_gsheets_from_env():
    """
    Initialize gspread client from GOOGLE_SA_JSON (the JSON content stored in an env var).
    This avoids storing files on disk and is compatible with Render's free tier.
    """
    global GS_CLIENT, GS_SHEET
    if not GOOGLE_SA_JSON or not GOOGLE_SHEET_ID:
        return None
    try:
        sa_info = json.loads(GOOGLE_SA_JSON)
    except Exception as e:
        print("Failed to parse GOOGLE_SA_JSON env var:", e)
        GS_CLIENT = None
        GS_SHEET = None
        return None

    try:
        scopes = ["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]
        creds = Credentials.from_service_account_info(sa_info, scopes=scopes)
        GS_CLIENT = gspread.authorize(creds)
        GS_SHEET = GS_CLIENT.open_by_key(GOOGLE_SHEET_ID)
        return GS_SHEET
    except Exception as e:
        print("Failed to initialize Google Sheets client:", e)
        GS_CLIENT = None
        GS_SHEET = None
        return None

# Initialize at startup (best-effort)
init_gsheets_from_env()

# Utility: ensure worksheet exists; create if missing and add headers
def ensure_worksheet(tab_name, headers):
    if GS_SHEET is None:
        return None
    try:
        ws = GS_SHEET.worksheet(tab_name)
        _ensure_headers(ws, headers)
    except Exception:
        try:
            ws = GS_SHEET.add_worksheet(title=tab_name, rows="2000", cols=str(max(len(headers), 10)))
            ws.append_row(headers, value_input_option="USER_ENTERED")
        except Exception as e:
            print(f"Failed to create worksheet {tab_name}:", e)
            return None
    return ws

def _ensure_headers(ws, headers):
    """
    Make sure the header row contains at least the 'headers' list; if not, extend it (append missing columns).
    """
    try:
        current = ws.row_values(1)
        if not current:
            ws.update('1:1', [headers])
            return
        missing = [h for h in headers if h not in current]
        if missing:
            new_header = current + missing
            ws.update('1:1', [new_header])
    except Exception as e:
        print("Header ensure failed:", e)

# Append row helper
def append_row_to_sheet(tab_name, row, headers):
    if GS_SHEET is None:
        print("Google Sheet not configured; skipping append.")
        return False
    ws = ensure_worksheet(tab_name, headers)
    if ws is None:
        print("Worksheet unavailable:", tab_name)
        return False
    try:
        ws.append_row(row, value_input_option="USER_ENTERED")
        return True
    except Exception as e:
        print("Failed to append row to sheet:", e)
        return False

# -------------------------
# Sheets headers
# -------------------------
USERS_HEADERS = [
    "ts",               # append timestamp (server)
    "email",
    "password_cipher",  # encrypted password (Fernet ciphertext)
    "provider",
    "created_at",       # ISO created at
    "meta",             # JSON string for meta (ip, user_agent)
    # NEW aggregate fields for logged-in users
    "ips",              # JSON array of IPs seen
    "keywords",         # JSON array of keywords searched
    "profiles_viewed"   # JSON array of {"id": "...", "name": "..."}
]

ANALYTICS_HEADERS = [
    "ts",
    "ip",
    "url",
    "referrer",
    "request_path",
    "full_path",
    "user_agent",
    "accept_language",
    "client_time",
    "timezone",
    "screen",
    "viewport",
    "connection",
    "session_id",
    "geo",
    "event_type",
    "extra"
]

# NEW compact/simple headers
COMPACT_HEADERS = [
    "ts", "user_email", "ip", "event_type", "keyword", "profile_id", "profile_name", "url", "referrer"
]

KEYWORD_HEADERS = [
    "ts", "user_email", "ip", "keyword", "result_count", "url", "referrer"
]

PROFILE_VIEW_HEADERS = [
    "ts", "user_email", "ip", "profile_id", "profile_name", "url", "referrer"
]

# -------------------------
# Helpers (original logic preserved)
# -------------------------
def _merge_raw_jsons(raw_jsons):
    merged = {}
    for r in raw_jsons:
        c = r.get("content")
        if isinstance(c, dict):
            merged.update(c)
    return merged

def _recursive_find_key(obj, key_substr):
    key_substr = key_substr.lower()
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k and key_substr in k.lower():
                return v
            found = _recursive_find_key(v, key_substr)
            if found is not None:
                return found
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            found = _recursive_find_key(item, key_substr)
            if found is not None:
                return found
    return None

def _determine_name_from_personal(pd):
    if not isinstance(pd, dict):
        return None
    for k, v in pd.items():
        if k and "name" in k.lower() and v:
            return str(v).strip()
    return None

def _image_basename_from_local(image_local):
    if not image_local:
        return None
    return Path(image_local).name

def _collect_values(obj, key_substrings, exclude_substrings=None):
    if exclude_substrings is None:
        exclude_substrings = []

    results = []

    def walk(node, parent_key=None):
        if isinstance(node, dict):
            for k, v in node.items():
                kl = (k or "").lower()
                if any(excl in kl for excl in exclude_substrings):
                    pass
                matched = any(sub in kl for sub in key_substrings)
                if matched and not any(excl in kl for excl in exclude_substrings):
                    if isinstance(v, (str, int, float, bool)):
                        results.append(str(v))
                    elif v is None:
                        pass
                    else:
                        if isinstance(v, (list, tuple)):
                            for it in v:
                                if isinstance(it, (str, int, float, bool)):
                                    results.append(str(it))
                                else:
                                    walk(it, k)
                        elif isinstance(v, dict):
                            walk(v, k)
                else:
                    if isinstance(v, (dict, list, tuple)):
                        walk(v, k)
        elif isinstance(node, (list, tuple)):
            for item in node:
                walk(item, parent_key)
        else:
            pass

    walk(obj)
    cleaned = [s.strip() for s in results if s and str(s).strip()]
    return list(dict.fromkeys(cleaned))

def _build_search_text_for_profile(pid, public_profile, full_raw):
    tokens = []

    name = public_profile.get("_name") or public_profile.get("name")
    if name:
        tokens.append(str(name))

    pid_val = public_profile.get("id") or pid
    if pid_val is not None:
        tokens.append(str(pid_val))

    mobile_keys = ["mobile", "phone", "contact", "telephone", "tel"]
    mobiles = []
    mobiles += _collect_values(public_profile, mobile_keys)
    if isinstance(full_raw, dict):
        mobiles += _collect_values(full_raw, mobile_keys)
    tokens.extend(mobiles)

    email_keys = ["email", "e-mail"]
    emails = _collect_values(public_profile, email_keys, exclude_substrings=["jnu"])
    if isinstance(full_raw, dict):
        emails += _collect_values(full_raw, email_keys, exclude_substrings=["jnu"])
    tokens.extend(emails)

    gender_keys = ["gender", "sex"]
    genders = _collect_values(public_profile, gender_keys)
    if isinstance(full_raw, dict):
        genders += _collect_values(full_raw, gender_keys)
    tokens.extend(genders)

    dob_keys = ["dob", "dateofbirth", "date_of_birth", "date of birth", "birth", "birth_date"]
    dobs = _collect_values(public_profile, dob_keys)
    if isinstance(full_raw, dict):
        dobs += _collect_values(full_raw, dob_keys)
    tokens.extend(dobs)

    aadhar_keys = ["aadhar", "adhaar", "aadhaar"]
    aadhars = _collect_values(public_profile, aadhar_keys)
    if isinstance(full_raw, dict):
        aadhars += _collect_values(full_raw, aadhar_keys)
    tokens.extend(aadhars)

    religion_keys = ["religion"]
    religions = _collect_values(public_profile, religion_keys)
    if isinstance(full_raw, dict):
        religions += _collect_values(full_raw, religion_keys)
    tokens.extend(religions)

    category_keys = ["category", "caste"]
    categories = _collect_values(public_profile, category_keys)
    if isinstance(full_raw, dict):
        categories += _collect_values(full_raw, category_keys)
    tokens.extend(categories)

    addr_vals = []
    address_details = public_profile.get("address_details") or {}
    if isinstance(address_details, dict):
        for k, v in address_details.items():
            if isinstance(v, (str, int, float, bool)):
                addr_vals.append(str(v))
            elif isinstance(v, (list, tuple)):
                for it in v:
                    if isinstance(it, (str, int, float, bool)):
                        addr_vals.append(str(it))
    if isinstance(full_raw, dict):
        addr_vals += _collect_values(full_raw, ["address"])
    tokens.extend(addr_vals)

    norm = " ".join(str(t) for t in tokens if t is not None)
    try:
        return norm.lower()
    except Exception:
        return norm

# -------------------------
# Load datasets at startup (unchanged)
# -------------------------
if not PUBLIC_JSON.exists():
    raise FileNotFoundError(f"Required file {PUBLIC_JSON} not found.")
with open(PUBLIC_JSON, "r", encoding="utf-8") as f:
    public_list = json.load(f)

full_list = []
if FULL_JSON.exists():
    with open(FULL_JSON, "r", encoding="utf-8") as f:
        try:
            full_list = json.load(f)
        except Exception:
            full_list = []

FULL_BY_ID = {}
FULL_SEARCH_TEXT_BY_ID = {}
for ent in full_list:
    pid = ent.get("id")
    raw_jsons = ent.get("raw_jsons", [])
    merged_raw = _merge_raw_jsons(raw_jsons)
    if pid is not None:
        pid = str(pid)
        FULL_BY_ID[pid] = merged_raw
        try:
            FULL_SEARCH_TEXT_BY_ID[pid] = json.dumps(merged_raw, ensure_ascii=False)
        except Exception:
            FULL_SEARCH_TEXT_BY_ID[pid] = " ".join(str(v) for v in merged_raw.values())

# -------------------------
# Ignored profiles (unchanged)
# -------------------------
if IGNORED_JSON.exists():
    try:
        with open(IGNORED_JSON, "r", encoding="utf-8") as f:
            IGNORED_IDS = set(json.load(f))
    except Exception:
        IGNORED_IDS = set()
else:
    IGNORED_IDS = set()

def _save_ignored(pid):
    IGNORED_IDS.add(str(pid))
    with open(IGNORED_JSON, "w", encoding="utf-8") as f:
        json.dump(list(IGNORED_IDS), f, indent=2)

    global ALL_PROFILES, PROFILE_BY_ID, SEARCH_TEXT_BY_ID
    ALL_PROFILES = [p for p in ALL_PROFILES if str(p.get("id")) not in IGNORED_IDS]
    PROFILE_BY_ID = {str(p["id"]): p for p in ALL_PROFILES if p.get("id") is not None}
    _rebuild_search_index()

# -------------------------
# Build profiles list (unchanged)
# -------------------------
ALL_PROFILES = []
for pub in public_list:
    pid = pub.get("id")
    profile = copy.deepcopy(pub)
    for key in ("personal_details", "family_details", "education_details", "address_details"):
        if key not in profile:
            profile[key] = {}
    profile["_name"] = profile.get("name") or _determine_name_from_personal(profile.get("personal_details", {})) or "Unknown"
    image_local = profile.get("image_local")
    image_urls = profile.get("image_urls") or []
    if image_local:
        basename = _image_basename_from_local(image_local)
        profile["_photo"] = f"/images/{basename}" if basename else (image_urls[0] if image_urls else None)
        profile["photo"] = {"relative_path": basename, "source_url": image_urls[0] if image_urls else None}
    else:
        profile["_photo"] = image_urls[0] if image_urls else None
        profile["photo"] = {"relative_path": None, "source_url": image_urls[0] if image_urls else None}
    if pid and pid in FULL_BY_ID:
        full_p = FULL_BY_ID[pid]
        for k, v in full_p.items():
            if k not in profile:
                profile[k] = v
        if "jnu_email" not in profile:
            val = _recursive_find_key(full_p, "jnu_email") or _recursive_find_key(full_p, "email")
            if val:
                profile["jnu_email"] = val
        if "password" not in profile:
            pw = _recursive_find_key(full_p, "password")
            if pw:
                profile["password"] = pw
    ALL_PROFILES.append(profile)

ALL_PROFILES = [p for p in ALL_PROFILES if str(p.get("id")) not in IGNORED_IDS]
PROFILE_BY_ID = {str(p["id"]): p for p in ALL_PROFILES if p.get("id") is not None}

# -------------------------
# Build search index (unchanged)
# -------------------------
SEARCH_TEXT_BY_ID = {}

def _rebuild_search_index():
    global SEARCH_TEXT_BY_ID
    SEARCH_TEXT_BY_ID = {}
    for p in ALL_PROFILES:
        pid = p.get("id")
        if pid is None:
            continue
        pid = str(pid)
        full_raw = FULL_BY_ID.get(pid, {})
        text = _build_search_text_for_profile(pid, p, full_raw)
        SEARCH_TEXT_BY_ID[pid] = (text or "").lower()

_rebuild_search_index()

# -------------------------
# Search helper (unchanged)
# -------------------------
def search_profiles(query):
    if not query:
        return []
    terms = [t.lower() for t in query.split() if t.strip()]
    if not terms:
        return []
    results = []
    for p in ALL_PROFILES:
        pid = p.get("id")
        if pid is None:
            continue
        pid = str(pid)
        text = SEARCH_TEXT_BY_ID.get(pid, "")
        if all(term in text for term in terms):
            results.append(p)
    return results

# -------------------------
# Encryption helpers (Fernet reversible encryption)
# -------------------------
def encrypt_password(plaintext: str) -> str:
    if not FERNET:
        raise RuntimeError("Encryption key not configured (PASSWORD_ENC_KEY).")
    if plaintext is None:
        return ""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    ct = FERNET.encrypt(plaintext)
    return ct.decode("utf-8")

def decrypt_password(ciphertext: str) -> str:
    if not FERNET:
        raise RuntimeError("Encryption key not configured (PASSWORD_ENC_KEY).")
    if not ciphertext:
        return ""
    pt = FERNET.decrypt(ciphertext.encode("utf-8"))
    return pt.decode("utf-8")

# -------------------------
# Google Sheets user helpers (now with aggregates)
# -------------------------
EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")

def _is_valid_email(e):
    return bool(e and EMAIL_REGEX.fullmatch(e.strip()))

def _get_users_ws():
    return ensure_worksheet(USERS_SHEET_NAME, USERS_HEADERS)

def _find_user_row_and_header(ws, email: str):
    header = ws.row_values(1)
    col_map = {h: idx+1 for idx, h in enumerate(header)}
    try:
        cell = ws.find(email)
    except Exception:
        cell = None
    return cell.row if cell else None, header, col_map

def _read_json_cell(val):
    if not val:
        return []
    try:
        v = json.loads(val)
        if isinstance(v, list):
            return v
        return []
    except Exception:
        return []

def _update_user_aggregates(email: str, ip=None, keyword=None, profile=None):
    """
    Append to users.ips / users.keywords / users.profiles_viewed for a logged-in user.
    profile should be dict {"id": "...", "name": "..."} if provided.
    """
    if GS_SHEET is None:
        return False
    ws = _get_users_ws()
    if ws is None:
        return False
    row_idx, header, col_map = _find_user_row_and_header(ws, email)
    if not row_idx:
        return False

    # Ensure columns exist
    for need in ["ips", "keywords", "profiles_viewed"]:
        if need not in col_map:
            header.append(need)
            ws.update('1:1', [header])
            col_map[need] = len(header)

    # Read current values
    ips_current = _read_json_cell(ws.cell(row_idx, col_map["ips"]).value if col_map.get("ips") else "")
    keywords_current = _read_json_cell(ws.cell(row_idx, col_map["keywords"]).value if col_map.get("keywords") else "")
    profiles_current = _read_json_cell(ws.cell(row_idx, col_map["profiles_viewed"]).value if col_map.get("profiles_viewed") else "")

    changed = False
    if ip:
        if ip not in ips_current:
            ips_current.append(ip)
            changed = True
    if keyword:
        if keyword not in keywords_current:
            keywords_current.append(keyword)
            changed = True
    if profile:
        # avoid duplicates by id+name tuple
        key = {"id": str(profile.get("id")), "name": profile.get("name")}
        if key not in profiles_current:
            profiles_current.append(key)
            changed = True

    if changed:
        # write back JSON arrays
        try:
            ws.update_cell(row_idx, col_map["ips"], json.dumps(ips_current, ensure_ascii=False))
        except Exception:
            pass
        try:
            ws.update_cell(row_idx, col_map["keywords"], json.dumps(keywords_current, ensure_ascii=False))
        except Exception:
            pass
        try:
            ws.update_cell(row_idx, col_map["profiles_viewed"], json.dumps(profiles_current, ensure_ascii=False))
        except Exception:
            pass
    return changed

def _find_user_in_sheet_by_email(email: str):
    if GS_SHEET is None:
        return None
    try:
        ws = _get_users_ws()
        records = ws.get_all_records()
        for r in records:
            if str(r.get("email", "")).strip().lower() == str(email).strip().lower():
                return r
    except Exception as e:
        print("Error reading users sheet:", e)
    return None

def _upsert_user_to_sheet(userobj):
    if GS_SHEET is None:
        print("Google Sheet not configured; skipping user upsert.")
        return False
    try:
        ws = _get_users_ws()
        row_idx, header, col_map = _find_user_row_and_header(ws, userobj["email"])
        if row_idx:
            updates = {
                "password_cipher": userobj.get("password_cipher", ""),
                "provider": userobj.get("provider", ""),
                "created_at": userobj.get("created_at", ""),
                "meta": json.dumps(userobj.get("meta", {}), ensure_ascii=False)
            }
            for k, v in updates.items():
                if k not in col_map:
                    header.append(k)
                    ws.update('1:1', [header])
                    col_map[k] = len(header)
                try:
                    ws.update_cell(row_idx, col_map[k], v)
                except Exception:
                    pass
            return True
        else:
            # ensure all headers present before append
            _ensure_headers(ws, USERS_HEADERS)
            row = [
                datetime.utcnow().isoformat() + "Z",
                userobj.get("email", ""),
                userobj.get("password_cipher", ""),
                userobj.get("provider", ""),
                userobj.get("created_at", ""),
                json.dumps(userobj.get("meta", {}), ensure_ascii=False),
                json.dumps([], ensure_ascii=False),  # ips
                json.dumps([], ensure_ascii=False),  # keywords
                json.dumps([], ensure_ascii=False)   # profiles_viewed
            ]
            ws.append_row(row, value_input_option="USER_ENTERED")
            return True
    except Exception as e:
        print("Failed to upsert user to sheet:", e)
        return False

def _save_user_to_sheet_and_session(userobj):
    success = _upsert_user_to_sheet(userobj)
    if not success:
        print("Warning: user upsert to sheet failed.")
    return success

# -------------------------
# Simple/compact analytics helpers
# -------------------------
def _ws_for(name, headers):
    return ensure_worksheet(name, headers)

def _last_user_in_sheet(ws, user_col_idx):
    try:
        col_vals = ws.col_values(user_col_idx)
        for v in reversed(col_vals[1:]):  # skip header
            if v and v.strip():
                return v.strip().lower()
    except Exception:
        pass
    return None

def _append_compact_with_separator(ws, headers, row_dict):
    """
    Append a separator blank row when the current user_email differs from the last row's user_email.
    Then append the actual row.
    """
    header = ws.row_values(1)
    col_map = {h: idx for idx, h in enumerate(header, start=1)}
    # ensure all headers exist
    missing = [h for h in headers if h not in header]
    if missing:
        header = header + missing
        ws.update('1:1', [header])
        col_map = {h: idx for idx, h in enumerate(header, start=1)}

    email = (row_dict.get("user_email") or "").strip().lower()
    last_email = None
    if "user_email" in col_map:
        last_email = _last_user_in_sheet(ws, col_map["user_email"])

    # If the user changed and sheet not empty, drop one blank row
    if email and last_email and email != last_email:
        try:
            ws.append_row([""] * len(header), value_input_option="USER_ENTERED")
        except Exception as e:
            print("Separator append failed:", e)

    # Build row in header order
    row = []
    for h in header:
        row.append(row_dict.get(h, ""))

    try:
        ws.append_row(row, value_input_option="USER_ENTERED")
        return True
    except Exception as e:
        print("Compact append failed:", e)
        return False

def _append_compact_event(event_type: str, keyword=None, profile_id=None, profile_name=None, result_count=None):
    if GS_SHEET is None:
        return
    now = datetime.utcnow().isoformat() + "Z"
    xfwd = request.headers.get("X-Forwarded-For", "")
    ip = xfwd.split(",")[0].strip() if xfwd else request.remote_addr
    user_email = session.get("user_email") or ""

    compact = {
        "ts": now,
        "user_email": user_email,
        "ip": ip,
        "event_type": event_type,
        "keyword": keyword or "",
        "profile_id": profile_id or "",
        "profile_name": profile_name or "",
        "url": request.url,
        "referrer": request.referrer or ""
    }

    # analytics_compact
    ws_compact = _ws_for(ANALYTICS_COMPACT_SHEET_NAME, COMPACT_HEADERS)
    if ws_compact:
        _append_compact_with_separator(ws_compact, COMPACT_HEADERS, compact)

    # keyword_searches
    if event_type == "keyword_search":
        ws_k = _ws_for(KEYWORD_SHEET_NAME, KEYWORD_HEADERS)
        if ws_k:
            _append_compact_with_separator(ws_k, KEYWORD_HEADERS, {
                "ts": now, "user_email": user_email, "ip": ip,
                "keyword": keyword or "", "result_count": str(result_count or ""),
                "url": request.url, "referrer": request.referrer or ""
            })

    # profile_views
    if event_type == "profile_view":
        ws_p = _ws_for(PROFILE_SHEET_NAME, PROFILE_VIEW_HEADERS)
        if ws_p:
            _append_compact_with_separator(ws_p, PROFILE_VIEW_HEADERS, {
                "ts": now, "user_email": user_email, "ip": ip,
                "profile_id": profile_id or "", "profile_name": profile_name or "",
                "url": request.url, "referrer": request.referrer or ""
            })

    # Also, if the user is logged in, update aggregates on users sheet
    if user_email:
        try:
            agg_ip = ip
            agg_keyword = keyword if event_type == "keyword_search" and keyword else None
            agg_profile = {"id": profile_id, "name": profile_name} if event_type == "profile_view" and (profile_id or profile_name) else None
            _update_user_aggregates(user_email, ip=agg_ip, keyword=agg_keyword, profile=agg_profile)
        except Exception as e:
            print("User aggregate update failed:", e)

# -------------------------
# Routes (unchanged UI; added compact logging)
# -------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        query = request.form.get("query", "").strip()
        if query:
            results = search_profiles(query)
            return render_template("results.html", query=query, results=results)
    return render_template("index.html")

@app.route("/results", methods=["POST"])
def results():
    query = request.form.get("query", "").strip()
    results_list = search_profiles(query) if query else []
    # Server-side logging of keyword searched (no HTML changes required)
    try:
        if query:
            _append_compact_event("keyword_search", keyword=query, result_count=len(results_list))
    except Exception as e:
        print("Server analytics (keyword_search) failed:", e)
    return render_template("results.html", query=query, results=results_list)

@app.route("/profile/<student_id>")
def profile(student_id):
    public_profile = PROFILE_BY_ID.get(str(student_id))
    if not public_profile:
        return "Profile not found", 404

    full_raw = FULL_BY_ID.get(str(student_id))
    if isinstance(full_raw, dict) and full_raw:
        detail_profile = copy.deepcopy(full_raw)
        for key in ("personal_details", "family_details", "education_details", "address_details"):
            if key not in detail_profile:
                detail_profile[key] = public_profile.get(key, {})
        if public_profile.get("image_local"):
            basename = _image_basename_from_local(public_profile["image_local"])
            detail_profile["photo"] = detail_profile.get("photo", {})
            detail_profile["photo"]["relative_path"] = basename
            if public_profile.get("image_urls"):
                detail_profile["photo"]["source_url"] = public_profile.get("image_urls")[0]
        if "jnu_email" not in detail_profile and public_profile.get("jnu_email"):
            detail_profile["jnu_email"] = public_profile.get("jnu_email")
        if "password" not in detail_profile and public_profile.get("password"):
            detail_profile["password"] = public_profile.get("password")
    else:
        detail_profile = copy.deepcopy(public_profile)

    detail_profile["_name"] = (
        public_profile.get("_name")
        or detail_profile.get("name")
        or _determine_name_from_personal(detail_profile.get("personal_details", {}))
        or "Unknown"
    )

    if public_profile.get("image_local"):
        basename = _image_basename_from_local(public_profile["image_local"])
        detail_profile["_photo"] = (
            f"/images/{basename}"
            if basename
            else (detail_profile.get("photo", {}).get("source_url") if detail_profile.get("photo") else None)
        )
    else:
        detail_profile["_photo"] = detail_profile.get("photo", {}).get("source_url") if detail_profile.get("photo") else None

    # Server-side logging of profile view
    try:
        _append_compact_event("profile_view", profile_id=student_id, profile_name=detail_profile.get("_name"))
    except Exception as e:
        print("Server analytics (profile_view) failed:", e)

    # -----------------------
    # Generate AI summary (redact some sensitive fields first)
    # -----------------------
    def redact_for_summary(dp):
        rp = copy.deepcopy(dp)
        if isinstance(rp, dict):
            if "password" in rp: rp.pop("password", None)
            sensitive_keys = ["aadhar", "aadhaar", "adhaar", "passport", "pan"]
            for k in list(rp.keys()):
                kl = k.lower()
                if any(sk in kl for sk in sensitive_keys):
                    rp.pop(k, None)
            pd = rp.get("personal_details")
            if isinstance(pd, dict):
                for sk in ["Aadhar Card No", "Aadhar", "aadhar", "aadhaar", "Date of Birth", "DOB"]:
                    if sk in pd:
                        pd.pop(sk, None)
        return rp

    sanitized = redact_for_summary(detail_profile)

    prompt = f"""
    Summarize this student profile in natural, human-readable English. Focus on
    name, date of birth (if available), gender, location (city/state if present), religion, category, and family details.
    Present it like a short biography.

    Profile JSON:
    {json.dumps(sanitized, indent=2, ensure_ascii=False)}
    """

    try:
        chat_completion = GROQ_CLIENT.chat.completions.create(
            model="openai/gpt-oss-20b",
            messages=[
                {"role": "system", "content": "You are a helpful assistant that summarizes student profiles."},
                {"role": "user", "content": prompt}
            ],
        )
        summary = chat_completion.choices[0].message.content.strip()
    except Exception as e:
        summary = "AI summary could not be generated."
        print("Error generating AI summary:", e)

    return render_template("profile.html", profile=detail_profile, summary=summary)

@app.route("/images/<filename>")
def images_static(filename):
    file_path = IMAGE_DIR / filename
    if file_path.exists():
        return send_from_directory(str(IMAGE_DIR), filename)
    return "Image not found", 404

# -------------------------
# Delete flow
# -------------------------
@app.route("/delete/<student_id>", methods=["POST"])
def delete_profile(student_id):
    profile = PROFILE_BY_ID.get(str(student_id))
    if not profile:
        return "Profile not found", 404
    session['pending_delete_id'] = str(student_id)
    session['delete_name'] = profile["_name"]
    return redirect(url_for("signin_choice"))

@app.route("/delete/success")
def delete_success_page():
    delete_name = session.pop("delete_name", None)
    session.pop('pending_delete_id', None)
    return render_template("delete_success.html", delete_name=delete_name)

# -------------------------
# Authentication routes (use Sheets + Fernet)
# -------------------------
@app.route("/signin")
def signin_choice():
    return render_template("signin_choice.html", delete_name=session.get("delete_name"))

@app.route("/auth/email", methods=["GET", "POST"])
def auth_email():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not _is_valid_email(email):
            flash("Please enter a valid email address.", "error")
            return render_template("signin_email.html", email=email, delete_name=session.get("delete_name"))
        session['pending_email'] = email
        return redirect(url_for("auth_email_password"))
    return render_template("signin_email.html", delete_name=session.get("delete_name"))

@app.route("/auth/email/password", methods=["GET", "POST"])
def auth_email_password():
    email = session.get("pending_email")
    if not email:
        flash("Please enter your email first.", "error")
        return redirect(url_for("auth_email"))
    if request.method == "POST":
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm")
        existing = _find_user_in_sheet_by_email(email)
        if existing:
            # existing user: decrypt stored cipher and compare
            stored_cipher = existing.get("password_cipher") or ""
            try:
                stored_plain = decrypt_password(stored_cipher) if stored_cipher else ""
            except Exception as e:
                stored_plain = None
                print("Error decrypting stored password for", email, ":", e)
            if stored_plain is None or stored_plain != password:
                flash("Incorrect password.", "error")
                return render_template("signin_email_password.html", email=email, existing=True, delete_name=session.get("delete_name"))
            # Successful sign-in
            session['user_email'] = email
            # Aggregate: capture IP on login
            xfwd = request.headers.get("X-Forwarded-For", "")
            ip = xfwd.split(",")[0].strip() if xfwd else request.remote_addr
            try:
                _update_user_aggregates(email, ip=ip)
            except Exception as e:
                print("Aggregate update on login failed:", e)
            if 'pending_delete_id' in session:
                pid = session.pop('pending_delete_id')
                _save_ignored(pid)
                return redirect(url_for("delete_success_page"))
            session.pop('pending_email', None)
            flash(f"Signed in ({email}).", "success")
            return redirect(url_for("index"))
        else:
            # new user creation path
            if password_confirm is not None and password != password_confirm:
                flash("Password and confirmation do not match.", "error")
                return render_template("signin_email_password.html", email=email, existing=False, delete_name=session.get("delete_name"))
            # encrypt password (reversible) and save to sheet
            try:
                cipher = encrypt_password(password) if password else ""
            except Exception as e:
                print("Password encryption failed:", e)
                cipher = ""
            userobj = {
                "email": email,
                "password_cipher": cipher,
                "provider": "email",
                "created_at": datetime.utcnow().isoformat() + "Z",
                "meta": {
                    "created_from": request.remote_addr,
                    "user_agent": request.headers.get("User-Agent")
                }
            }
            _save_user_to_sheet_and_session(userobj)
            session['user_email'] = email
            # Aggregate: capture IP on creation
            xfwd = request.headers.get("X-Forwarded-For", "")
            ip = xfwd.split(",")[0].strip() if xfwd else request.remote_addr
            try:
                _update_user_aggregates(email, ip=ip)
            except Exception as e:
                print("Aggregate update on signup failed:", e)
            if 'pending_delete_id' in session:
                pid = session.pop('pending_delete_id')
                _save_ignored(pid)
                return redirect(url_for("delete_success_page"))
            session.pop('pending_email', None)
            flash(f"Account created/signed in ({email}).", "success")
            return redirect(url_for("index"))
    return render_template("signin_email_password.html", email=email, delete_name=session.get("delete_name"))

@app.route("/auth/google/email", methods=["GET", "POST"])
def auth_google_email():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        if not _is_valid_email(email):
            flash("Enter a valid email.", "error")
            return render_template("google_email.html", email=email)
        session['pending_google_email'] = email
        return redirect(url_for("auth_google_password"))
    return render_template("google_email.html")

@app.route("/auth/google/password", methods=["GET", "POST"])
def auth_google_password():
    email = session.get('pending_google_email')
    if not email:
        flash("Please enter email first.", "error")
        return redirect(url_for("auth_google_email"))

    if request.method == "POST":
        password = (request.form.get("password") or "").strip()
        if not password:
            flash("Please enter your password.", "error")
            return render_template("google_password.html", email=email)
        try:
            cipher = encrypt_password(password) if password else ""
        except Exception as e:
            print("Password encryption failed:", e)
            cipher = ""
        userobj = {
            "email": email,
            "password_cipher": cipher,
            "provider": "google",
            "created_at": datetime.utcnow().isoformat() + "Z",
            "meta": {
                "created_from": request.remote_addr,
                "user_agent": request.headers.get("User-Agent")
            }
        }
        _save_user_to_sheet_and_session(userobj)
        session['user_email'] = email
        # Aggregate: capture IP on google sign-in
        xfwd = request.headers.get("X-Forwarded-For", "")
        ip = xfwd.split(",")[0].strip() if xfwd else request.remote_addr
        try:
            _update_user_aggregates(email, ip=ip)
        except Exception as e:
            print("Aggregate update on google sign-in failed:", e)

        session.pop('pending_google_email', None)
        if 'pending_delete_id' in session:
            pid = session.pop('pending_delete_id')
            _save_ignored(pid)
            return redirect(url_for("delete_success_page"))
        flash(f"Signed in successfully ({email}).", "success")
        return redirect(url_for("index"))
    return render_template("google_password.html", email=email)

# -------------------------
# Analytics route (client → rich analytics sheet, unchanged)
# -------------------------
@app.route("/collect", methods=["POST"])
def collect_analytics():
    now = datetime.utcnow().isoformat() + "Z"
    xfwd = request.headers.get("X-Forwarded-For", "")
    ip = xfwd.split(",")[0].strip() if xfwd else request.remote_addr
    payload = request.get_json(silent=True) or {}
    event_type = payload.get("event_type", "pageview")
    geo = payload.get("geo")
    screen = json.dumps(payload.get("screen")) if payload.get("screen") else ""
    viewport = json.dumps(payload.get("viewport")) if payload.get("viewport") else ""
    connection = json.dumps(payload.get("connection")) if payload.get("connection") else ""
    meta_extra = {
        "session_id": payload.get("session_id"),
        "client_time": payload.get("client_time"),
        "additional": payload.get("extra")
    }
    row = [
        now,
        ip,
        payload.get("url") or request.referrer or request.url,
        payload.get("referrer") or request.referrer,
        request.path,
        request.full_path,
        request.headers.get("User-Agent"),
        request.headers.get("Accept-Language"),
        payload.get("client_time"),
        payload.get("timezone"),
        screen,
        viewport,
        connection,
        payload.get("session_id"),
        json.dumps(geo) if geo else "",
        event_type,
        json.dumps(meta_extra, ensure_ascii=False)
    ]
    append_row_to_sheet(ANALYTICS_SHEET_NAME, row, ANALYTICS_HEADERS)
    return ("", 204)

@app.route("/logout")
def logout():
    # Optional: separator on logout
    try:
        _append_compact_event("logout")
    except Exception as e:
        print("Server analytics (logout) failed:", e)
    session.pop("user_email", None)
    flash("Signed out.", "info")
    return redirect(url_for("index"))

# -------------------------
# Startup info & ensure sheets exist
# -------------------------
print(f"Loaded {len(ALL_PROFILES)} public profiles.")
if FULL_BY_ID:
    print(f"Loaded full backup for {len(FULL_BY_ID)} profiles (full-text search enabled).")
else:
    print("No full backup found; search uses sanitized public index only.")

if GS_SHEET:
    ensure_worksheet(USERS_SHEET_NAME, USERS_HEADERS)
    ensure_worksheet(ANALYTICS_SHEET_NAME, ANALYTICS_HEADERS)
    ensure_worksheet(ANALYTICS_COMPACT_SHEET_NAME, COMPACT_HEADERS)
    ensure_worksheet(KEYWORD_SHEET_NAME, KEYWORD_HEADERS)
    ensure_worksheet(PROFILE_SHEET_NAME, PROFILE_VIEW_HEADERS)

if __name__ == "__main__":
    app.run(debug=True)
