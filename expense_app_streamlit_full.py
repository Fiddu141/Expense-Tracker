
#!/usr/bin/env python3
"""
Streamlit Expense Tracker — Firebase Auth (Email/Password) + Encrypted "Remember Me"
====================================================================================

Features
--------
• Login & Sign Up with Firebase Email/Password Authentication
• "Remember Me" — securely stores session (UID + email) encrypted with a passphrase
• Each user’s data is isolated: stored under /users/<UID>/... in Firebase Realtime Database
• Daily editable grid (one row per date, one column per category, totals)
• Add categories dynamically (no defaults)
• Monthly/Yearly summaries + bar & pie charts
• Cloud-synced across devices (mobile & laptop) via Firebase

Setup
-----
1) Firebase Console:
   - Enable Authentication → Sign-in method → Email/Password
   - Enable Realtime Database (test mode while prototyping)
   - Project Settings → Service Accounts → Generate new private key → copy JSON into Streamlit secrets
   - Project Settings → General → copy Web API Key

2) Streamlit Secrets (preferred) or Environment variables:
   FIREBASE_WEB_API_KEY="your_web_api_key"
   FIREBASE_DATABASE_URL="https://<your-db>.firebasedatabase.app/"
   firebase_service_account_json = """"""
   SESSION_SECRET="a-long-random-passphrase"  # used to encrypt the local 'remember me' session

Install
-------
pip install streamlit firebase-admin matplotlib pandas requests cryptography

Run
---
streamlit run expense_app_streamlit_auth.py
"""

from __future__ import annotations

import os
import json
from datetime import datetime, date
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from collections import defaultdict
from pathlib import Path
from typing import Optional, Tuple

import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import requests
import plotly.express as px

# Crypto for "Remember Me"
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

# Firebase Admin SDK (server-side DB access)
import firebase_admin
from firebase_admin import credentials, db

APP_TITLE = "Expense Tracker (Cloud-Synced, Multi-User)"
CURRENCY = "₹"
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
SESSION_FILE = Path(".session.enc")
KDF_SALT = b"streamlit-expense-tracker-salt-v1"  # static salt; okay for personal app (keep SESSION_SECRET secret)


# -------------------- Helpers: Money & Keys --------------------
def month_key(year: int, month_index: int) -> str:
    return f"{year:04d}-{month_index:02d}"


def format_money(d: Decimal) -> str:
    return f"{CURRENCY}{d.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP):,}"


def _derive_key(passphrase: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=KDF_SALT,
        iterations=390_000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def encrypt_session(data: dict, passphrase: str) -> bytes:
    key = _derive_key(passphrase)
    f = Fernet(key)
    token = f.encrypt(json.dumps(data).encode("utf-8"))
    return token


def decrypt_session(token: bytes, passphrase: str) -> Optional[dict]:
    try:
        key = _derive_key(passphrase)
        f = Fernet(key)
        payload = f.decrypt(token)
        return json.loads(payload.decode("utf-8"))
    except Exception:
        return None


def save_session(uid: str, email: str):
    secret = os.environ.get("SESSION_SECRET", None) or st.secrets.get("SESSION_SECRET", None)
    if not secret:
        st.warning("SESSION_SECRET missing — Remember Me cannot encrypt session. Add it to secrets to enable.")
        return
    blob = encrypt_session({"uid": uid, "email": email}, secret)
    SESSION_FILE.write_bytes(blob)


def load_saved_session() -> Optional[Tuple[str, str]]:
    """Returns (uid, email) if a valid encrypted session exists and can be decrypted; else None."""
    if not SESSION_FILE.exists():
        return None
    secret = os.environ.get("SESSION_SECRET", None) or st.secrets.get("SESSION_SECRET", None)
    if not secret:
        return None
    token = SESSION_FILE.read_bytes()
    payload = decrypt_session(token, secret)
    if payload and "uid" in payload and "email" in payload:
        return payload["uid"], payload["email"]
    return None


def clear_saved_session():
    try:
        if SESSION_FILE.exists():
            SESSION_FILE.unlink()
    except Exception:
        pass


# -------------------- Firebase Init (Admin) --------------------
@st.cache_resource(show_spinner=False)
def init_firebase_admin():
    if len(firebase_admin._apps) > 0:
        return firebase_admin.get_app()

    svc_json = None
    if "firebase_service_account_json" in st.secrets:
        svc_json = json.loads(st.secrets["firebase_service_account_json"])
    else:
        key_file = "firebase_key.json"
        if os.path.exists(key_file):
            with open(key_file, "r", encoding="utf-8") as f:
                svc_json = json.load(f)

    if not svc_json:
        raise RuntimeError("Service account JSON missing. Put firebase_key.json beside this script or in st.secrets.")

    database_url = os.environ.get("FIREBASE_DATABASE_URL") or st.secrets.get("FIREBASE_DATABASE_URL", None)
    if not database_url:
        raise RuntimeError("FIREBASE_DATABASE_URL not set. Add it to environment or st.secrets.")

    cred = credentials.Certificate(svc_json)
    app = firebase_admin.initialize_app(cred, {"databaseURL": database_url})
    return app


def fb_ref(uid: str, path: str):
    base = f"/users/{uid}"
    full = f"{base}/{path}".strip("/")
    return db.reference(full)


def fb_get(uid: str, path: str):
    return fb_ref(uid, path).get()


def fb_set(uid: str, path: str, value):
    fb_ref(uid, path).set(value)


def fb_update(uid: str, path: str, value_dict: dict):
    fb_ref(uid, path).update(value_dict)


# -------------------- Firebase Auth (REST) --------------------
def _api_key() -> str:
    key = os.environ.get("FIREBASE_WEB_API_KEY") or st.secrets.get("FIREBASE_WEB_API_KEY", None)
    if not key:
        raise RuntimeError("FIREBASE_WEB_API_KEY missing. Set it in environment or st.secrets.")
    return key


def firebase_sign_up(email: str, password: str) -> Tuple[str, str]:
    """Returns (uid, email)."""
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={_api_key()}"
    payload = {"email": email, "password": password, "returnSecureToken": True}
    r = requests.post(url, json=payload, timeout=20)
    if r.status_code != 200:
        raise RuntimeError(r.json().get("error", {}).get("message", "Sign up failed"))
    data = r.json()
    return data["localId"], data["email"]


def firebase_sign_in(email: str, password: str) -> Tuple[str, str]:
    """Returns (uid, email)."""
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={_api_key()}"
    payload = {"email": email, "password": password, "returnSecureToken": True}
    r = requests.post(url, json=payload, timeout=20)
    if r.status_code != 200:
        raise RuntimeError(r.json().get("error", {}).get("message", "Login failed"))
    data = r.json()
    return data["localId"], data["email"]


# -------------------- Data Model Helpers --------------------
DEFAULT_DATA = {"meta": {"categories": []}, "months": {}}


def load_all_data(uid: str) -> dict:
    data = fb_get(uid, "") or {}
    # self-heal
    if "meta" not in data: data["meta"] = {"categories": []}
    if "categories" not in data["meta"]: data["meta"]["categories"] = []
    if "months" not in data: data["months"] = {}
    return data


# Preferences stored at meta.prefs
PREFS_PATH = "meta/prefs"
DEFAULT_SORT = "High → Low (spent)"


def get_user_prefs(uid: str) -> dict:
    prefs = fb_get(uid, PREFS_PATH) or {}
    # ensure a default sort if none
    if "category_sort" not in prefs:
        prefs["category_sort"] = DEFAULT_SORT
    return prefs


def set_user_prefs(uid: str, prefs: dict) -> None:
    fb_update(uid, PREFS_PATH, prefs)


def ensure_month_exists(data: dict, mkey: str) -> None:
   # months = data.setdefault("months", {})
    if mkey not in data["months"]:
        data["months"][mkey] = {"income": "0", "dates": {}}
    if "income" not in data["months"][mkey]:
        data["months"][mkey]["income"] = "0"
    if "dates" not in data["months"][mkey]:
        data["months"][mkey]["dates"] = {}
    return data


def add_category_global(uid: str, data: dict, name: str) -> bool:
    name = (name or "").strip()
    if not name:
        return False
    cats = data["meta"].setdefault("categories", [])
    if name in cats:
        return False
    cats.append(name)
    # fill existing rows with default "0"
    for mkey, mval in data.get("months", {}).items():
        for dkey, row in mval.get("dates", {}).items():
            row.setdefault(name, "0")
    fb_set(uid, "", data)
    return True


def delete_date_row(uid: str, data: dict, mkey: str, dkey: str) -> None:
    try:
        del data["months"][mkey]["dates"][dkey]
    except KeyError:
        pass
    fb_set(uid, "", data)


def write_month_block(uid: str, data: dict, mkey: str) -> None:
    # db_ref = db.reference("/")
    # root = db_ref.child("users").child(uid).child("months").child(mkey).set(data["months"][mkey])
    # root = db_ref.child("users").child(uid).child("meta").set(data["months"][mkey])
    # root = {
    #     "meta": data["meta"],
    #     "months": {mkey: data["months"][mkey]}
    # }
    fb_update(uid, "meta", data["meta"])
    fb_update(uid, f"months/{mkey}", data["months"][mkey])

def init_user(uid):
    db_ref = db.reference("/")
    ref = db_ref.child("users").child(uid)
    data = ref.get() or {}
    if "meta" not in data:
        data["meta"] = {"categories": []}
    if "months" not in data:
        data["months"] = {}
    ref.set(data)
    return data
# -------------------- UI: Auth --------------------
def auth_gate() -> Optional[Tuple[str, str]]:
    """Returns (uid, email) if logged in or auto-logged; otherwise None."""
    # 1) Auto-login via Remember Me (encrypted file)
    saved = load_saved_session()
    if saved and "uid" not in st.session_state:
        uid, email = saved
        st.session_state["uid"] = uid
        st.session_state["email"] = email
        return uid, email

    st.header("Login / Sign Up")

    tab_login, tab_signup = st.tabs(["Login", "Sign Up"])
    with tab_login:
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        remember = st.checkbox("Remember Me (encrypted)", value=True, key="login_remember")
        if st.button("Login", type="primary"):
            try:
                uid, email = firebase_sign_in(email, password)
                st.session_state["uid"] = uid
                st.session_state["email"] = email
                init_user(uid)
                if remember:
                    save_session(uid, email)
                st.success("Logged in successfully.")
                st.experimental_rerun()
            except Exception as e:
                st.error(f"Login failed: {e}")

    with tab_signup:
        email2 = st.text_input("Email", key="signup_email")
        password2 = st.text_input("Password", type="password", key="signup_password")
        if st.button("Create Account"):
        # ✅ Initialize empty schema for new users
            DEFAULT_DATA = {"meta": {"categories": []}, "months": {}}
            try:
                uid, email_val = firebase_sign_up(email2, password2)
                # initialize user root if empty
                existing = fb_get(uid, "")
                if not existing:
                    fb_set(uid, "", DEFAULT_DATA)
                st.success("Account created. Please go to Login tab to sign in.")
            except Exception as e:
                st.error(f"Sign up failed: {e}")

    return None


# -------------------- UI: Core Tabs --------------------
def daily_tab(uid: str, data: dict):
    st.subheader("Daily Expenses")
    # Month & Year selectors
    today = datetime.now()
    years = list(range(2000, 2101))
    col1, col2, col3 = st.columns([1,1,2])

    with col1:
        year = st.selectbox("Year", years, index=years.index(today.year), key="daily_year")
    with col2:
        month_name = st.selectbox("Month", MONTHS, index=today.month - 1, key="daily_month")
        month_idx = MONTHS.index(month_name) + 1

    mkey = month_key(year, month_idx)
    ensure_month_exists(data, mkey)

    # Income
    with col3:
        income_str = st.text_input("Monthly Income", data["months"][mkey].get("income", "0"), key="daily_income")
        if st.button("Save Income", type="primary"):
            try:
                Decimal(income_str)
            except InvalidOperation:
                st.error("Please enter a valid number for income.")
            else:
                data["months"][mkey]["income"] = income_str
                write_month_block(uid, data, mkey)
                st.success("Income saved.")

    # Add Date row
    c1, c2 = st.columns([2,1])
    with c1:
        year, month = map(int, mkey.split("-"))
        new_date = st.date_input("Add Date", value=datetime(year, month, 1), key="add_date")
    with c2:
        if st.button("Insert Date Row"):
            dkey = new_date.strftime("%Y-%m-%d")
            ensure_month_exists(data, mkey)  # ✅ Fix KeyError
            dates = data["months"][mkey]["dates"]
            if dkey in dates:
                st.info(f"Date {dkey} already exists.")
            else:
                dates[dkey] = {c: "0" for c in data["meta"]["categories"]}
                write_month_block(uid, data, mkey)
                st.success(f"Added {dkey}")

    # Add Category
    st.markdown("---")
    colA, colB = st.columns([2,1])
    with colA:
        new_cat = st.text_input("Add Category (creates a new column)", key="new_category")
    with colB:
        if st.button("Add Category"):
            if add_category_global(uid, data, new_cat):
                st.success(f"Added category '{new_cat}'")
            else:
                st.warning("Category exists or name invalid.")

    # Build editable grid
    st.markdown("---")
    st.write(f"**Editing Month:** {mkey}")
    cats = data["meta"]["categories"]
    data = ensure_month_exists(data, mkey)  # ✅ Fix KeyError
    dates = data["months"][mkey]["dates"]

    # Category sorting controls
    sort_options = ["A → Z", "Z → A", "High → Low (spent)", "Low → High (spent)"]
    prefs = get_user_prefs(uid)
    default_idx = sort_options.index(prefs.get("category_sort", DEFAULT_SORT)) if prefs.get("category_sort", DEFAULT_SORT) in sort_options else 0
    sort_mode = st.selectbox("Category sort", sort_options, index=default_idx, key=f"daily_sort_{mkey}")
    if sort_mode != prefs.get("category_sort"):
        prefs["category_sort"] = sort_mode
        set_user_prefs(uid, prefs)
    spend_by_cat = {c: sum(Decimal(str(r.get(c, "0") or "0")) for r in dates.values()) for c in cats}
    if sort_mode == "A → Z":
        sorted_cats = sorted(cats)
    elif sort_mode == "Z → A":
        sorted_cats = sorted(cats, reverse=True)
    elif sort_mode == "High → Low (spent)":
        sorted_cats = sorted(cats, key=lambda c: spend_by_cat.get(c, Decimal(0)), reverse=True)
    else:
        sorted_cats = sorted(cats, key=lambda c: spend_by_cat.get(c, Decimal(0)))

    rows = []
    for dkey in sorted(dates.keys()):
        row = {"Date": dkey}
        for c in cats:
            row[c] = dates[dkey].get(c, "0")
        total = sum((Decimal(str(row[c])) if str(row[c]).strip() else Decimal(0)) for c in cats)
        row["Total"] = str(total)
        rows.append(row)
    df = pd.DataFrame(rows, columns=( ["Date"] + sorted_cats + ["Total"] )) if rows else pd.DataFrame(columns=( ["Date"] + sorted_cats + ["Total"] ))

    # KPIs for current month
    income_dec = Decimal(data["months"][mkey].get("income", "0") or "0")
    month_total_dec = sum(Decimal(str(r["Total"])) for r in rows) if rows else Decimal(0)
    remaining_dec = income_dec - month_total_dec
    c_k1, c_k2, c_k3, c_k4 = st.columns(4)
    c_k1.metric("Income", format_money(income_dec))
    c_k2.metric("Spent", format_money(month_total_dec))
    c_k3.metric("Remaining", format_money(remaining_dec))
    utilization_pct = (float(month_total_dec / income_dec * 100) if income_dec > 0 else 0.0)
    c_k4.metric("Utilization", f"{utilization_pct:.1f}%")

    # Prepare numeric editor with currency formatting
    df_display = df.copy()
    for _c in (sorted_cats + ["Total"]):
        if _c in df_display.columns:
            df_display[_c] = pd.to_numeric(df_display[_c], errors="coerce").fillna(0.0)
    col_config = { _c: st.column_config.NumberColumn(_c, step=0.01, format=f"{CURRENCY}%.2f") for _c in sorted_cats }
    col_config["Total"] = st.column_config.NumberColumn("Total", step=0.01, format=f"{CURRENCY}%.2f")

    st.write("### Daily Expenses")
    edited = st.data_editor(
        df_display,
        num_rows="dynamic",
        use_container_width=True,
        key=f"editor_{mkey}",
        disabled=["Total", "Date"],
        column_config=col_config,
    )

    csv_month = df.to_csv(index=False).encode("utf-8")
    st.download_button("Download Month CSV", csv_month, file_name=f"expenses_{mkey}.csv", mime="text/csv")

    # Save grid changes
    if st.button("Save Changes"):
        new_dates = {}
        for _, r in edited.iterrows():
            dkey = r["Date"]
            if not isinstance(dkey, str) or not dkey:
                continue
            new_dates[dkey] = {}
            for c in cats:
                val = str(r.get(c, "0"))
                try:
                    Decimal(val)
                except InvalidOperation:
                    val = "0"
                new_dates[dkey][c] = val
        data["months"][mkey]["dates"] = new_dates
        write_month_block(uid, data, mkey)
        st.success("Saved month changes.")

    # Delete selected row
    st.markdown("#### Delete a date row")
    del_date = st.selectbox("Select Date to Delete", [""] + sorted(dates.keys()), index=0, key="del_date_sel")
    if st.button("Delete Row") and del_date:
        delete_date_row(uid, data, mkey, del_date)
        st.success(f"Deleted {del_date}. Refresh the page to see the update.")

    st.markdown("---")
    st.info("Tip: Use 'Insert Date Row' to add dates. Edit numbers in the grid, then click 'Save Changes'.")


def monthly_tab(uid: str, data: dict):
    st.subheader("Monthly Summary")
    today = datetime.now()
    years = list(range(2000, 2101))
    c1, c2 = st.columns(2)
    with c1:
        year = st.selectbox("Year", years, index=years.index(today.year), key="msum_year")
    with c2:
        month_name = st.selectbox("Month", MONTHS, index=today.month - 1, key="msum_month")
    month_idx = MONTHS.index(month_name) + 1
    mkey = month_key(year, month_idx)
    ensure_month_exists(data, mkey)

    cats = data["meta"]["categories"]
    data = ensure_month_exists(data, mkey)  # ✅ Fix KeyError
    dates = data["months"][mkey]["dates"]
    income = Decimal(data["months"][mkey].get("income", "0") or "0")

    cat_totals = defaultdict(Decimal)
    for _, row in dates.items():
        for c in cats:
            try:
                cat_totals[c] += Decimal(str(row.get(c, "0")))
            except InvalidOperation:
                pass

    # Category sorting controls
    sort_options = ["A → Z", "Z → A", "High → Low (spent)", "Low → High (spent)"]
    prefs = get_user_prefs(uid)
    default_idx = sort_options.index(prefs.get("category_sort", DEFAULT_SORT)) if prefs.get("category_sort", DEFAULT_SORT) in sort_options else 0
    sort_mode = st.selectbox("Category sort", sort_options, index=default_idx, key=f"monthly_sort_{mkey}")
    if sort_mode != prefs.get("category_sort"):
        prefs["category_sort"] = sort_mode
        set_user_prefs(uid, prefs)
    if sort_mode == "A → Z":
        sorted_cats = sorted(cats)
    elif sort_mode == "Z → A":
        sorted_cats = sorted(cats, reverse=True)
    elif sort_mode == "High → Low (spent)":
        sorted_cats = sorted(cats, key=lambda c: cat_totals.get(c, Decimal(0)), reverse=True)
    else:
        sorted_cats = sorted(cats, key=lambda c: cat_totals.get(c, Decimal(0)))

    total_sum = sum(cat_totals.values())
    ratio = (total_sum / income * 100) if income > 0 else None

    tbl = pd.DataFrame({"Category": sorted_cats, "Total": [float(cat_totals[c]) for c in sorted_cats]})

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Income", format_money(income))
    k2.metric("Spent", format_money(Decimal(total_sum)))
    k3.metric("Remaining", format_money(income - Decimal(total_sum)))
    k4.metric("Expense Ratio", f"{ratio:.1f}%" if ratio is not None else "—")

    if cats:
        fig_bar = px.bar(tbl, x="Category", y="Total", title="Monthly Expenses by Category", text_auto=True)
        fig_bar.update_layout(xaxis_tickangle=-45, height=350, margin=dict(t=60, b=10))
        st.plotly_chart(fig_bar, use_container_width=True)

        if total_sum > 0:
            fig_pie = px.pie(tbl, names="Category", values="Total", title="Distribution", hole=0.4)
            st.plotly_chart(fig_pie, use_container_width=True)

    st.dataframe(tbl, use_container_width=True)
    csv = tbl.to_csv(index=False).encode("utf-8")
    st.download_button("Download Monthly Totals CSV", csv, file_name=f"monthly_{mkey}.csv", mime="text/csv")


def yearly_tab(uid: str, data: dict):
    st.subheader("Yearly Summary")
    today = datetime.now()
    years = list(range(2000, 2101))
    year = st.selectbox("Year", years, index=years.index(today.year), key="ysum_year")

    cats = data["meta"]["categories"]
    cat_totals = defaultdict(Decimal)
    total_income = Decimal(0)

    for m in range(1, 13):
        mkey = month_key(year, m)
        if mkey not in data["months"]:
            continue
        block = data["months"][mkey]
        try:
            total_income += Decimal(block.get("income", "0") or "0")
        except InvalidOperation:
            pass
        for _, row in block.get("dates", {}).items():
            for c in cats:
                try:
                    cat_totals[c] += Decimal(str(row.get(c, "0")))
                except InvalidOperation:
                    pass

    # Category sorting controls
    sort_options = ["A → Z", "Z → A", "High → Low (spent)", "Low → High (spent)"]
    prefs = get_user_prefs(uid)
    default_idx = sort_options.index(prefs.get("category_sort", DEFAULT_SORT)) if prefs.get("category_sort", DEFAULT_SORT) in sort_options else 0
    sort_mode = st.selectbox("Category sort", sort_options, index=default_idx, key=f"yearly_sort_{year}")
    if sort_mode != prefs.get("category_sort"):
        prefs["category_sort"] = sort_mode
        set_user_prefs(uid, prefs)
    if sort_mode == "A → Z":
        sorted_cats = sorted(cats)
    elif sort_mode == "Z → A":
        sorted_cats = sorted(cats, reverse=True)
    elif sort_mode == "High → Low (spent)":
        sorted_cats = sorted(cats, key=lambda c: cat_totals.get(c, Decimal(0)), reverse=True)
    else:
        sorted_cats = sorted(cats, key=lambda c: cat_totals.get(c, Decimal(0)))

    total_sum = sum(cat_totals.values())
    ratio = (total_sum / total_income * 100) if total_income > 0 else None

    tbl = pd.DataFrame({"Category": sorted_cats, "Total": [float(cat_totals[c]) for c in sorted_cats]})

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Total Income", format_money(total_income))
    k2.metric("Total Spent", format_money(Decimal(total_sum)))
    k3.metric("Savings", format_money(total_income - Decimal(total_sum)))
    k4.metric("Expense Ratio", f"{ratio:.1f}%" if ratio is not None else "—")

    if cats:
        fig_bar = px.bar(tbl, x="Category", y="Total", title="Yearly Expenses by Category", text_auto=True)
        fig_bar.update_layout(xaxis_tickangle=-45, height=350, margin=dict(t=60, b=10))
        st.plotly_chart(fig_bar, use_container_width=True)

        if total_sum > 0:
            fig_pie = px.pie(tbl, names="Category", values="Total", title="Distribution", hole=0.4)
            st.plotly_chart(fig_pie, use_container_width=True)

    st.dataframe(tbl, use_container_width=True)
    csv = tbl.to_csv(index=False).encode("utf-8")
    st.download_button("Download Yearly Totals CSV", csv, file_name=f"yearly_{year}.csv", mime="text/csv")


# -------------------- App --------------------
def main():
    st.set_page_config(page_title=APP_TITLE, page_icon="💸", layout="wide")
    st.title(APP_TITLE)

    # Firebase Admin for DB
    try:
        init_firebase_admin()
    except Exception as e:
        st.error(f"Firebase init failed: {e}")
        st.stop()

    # Auth (auto or interactive)
    auth = auth_gate()
    if not auth and "uid" not in st.session_state:
        st.stop()

    uid = st.session_state.get("uid")
    email = st.session_state.get("email")

    with st.sidebar:
        st.markdown("### Account")
        st.caption(f"Signed in as {email}")
        if st.button("Logout"):
            st.session_state.pop("uid", None)
            st.session_state.pop("email", None)
            clear_saved_session()
            st.experimental_rerun()
        st.markdown("---")
        st.markdown("### Navigation")
        st.caption("Use tabs on the right to switch views.")

    # Load data
    data = load_all_data(uid)
    if not data:
        data = DEFAULT_DATA
        fb_set(uid, "", data)

    # Tabs
    tab1, tab2, tab3 = st.tabs(["Daily", "Monthly Summary", "Yearly Summary"])
    with tab1:
        daily_tab(uid, data)
    with tab2:
        monthly_tab(uid, data)
    with tab3:
        yearly_tab(uid, data)

    st.caption("Your data root: /users/%s/  (private per account)" % uid)


if __name__ == "__main__":
    main()
