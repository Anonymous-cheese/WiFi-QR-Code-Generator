#!/usr/bin/env python3
# 746f617374

"""
WiFi QR Code Generator
- Generates iOS/Android-compatible Wi-Fi QR codes (no enterprise/802.1X)

Dependencies (install via pip):
  pip install customtkinter qrcode[pil] pillow

Optional (Windows image clipboard support):
  pip install pywin32
"""

from __future__ import annotations

import json
import os
import platform
import sys
import traceback
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# --- GUI imports (CustomTkinter preferred; Tkinter fallback) ---
USE_CTK = True
try:
    import customtkinter as ctk
except Exception:
    USE_CTK = False

import tkinter as tk
from tkinter import filedialog, messagebox

# --- QR / imaging ---
import qrcode
from qrcode.constants import ERROR_CORRECT_L, ERROR_CORRECT_M, ERROR_CORRECT_Q, ERROR_CORRECT_H
from PIL import Image, ImageTk

# SVG export via qrcode built-in SVG factory (no extra dep)
try:
    import qrcode.image.svg  # type: ignore
    HAS_SVG = True
except Exception:
    HAS_SVG = False


APP_TITLE = "WiFi QR Code Generator"
TAG_TEXT = "746f617374"

DEFAULT_INCHES = 2.0
DEFAULT_DPI = 300
DEFAULT_BORDER = 4
DEFAULT_ECC = "M"
PROFILES_MAX = 5

# Window size: 20% larger than previous 980x620 => 1176x744
DEFAULT_W = 1176
DEFAULT_H = 744

AUTH_OPTIONS = [
    "Open / None",
    "WEP (Legacy / Insecure)",
    "WPA/WPA2-Personal (PSK)",
    "WPA2-Personal (PSK)",
    "WPA3-Personal (SAE)",
    "WPA2/WPA3-Personal (Mixed)",
]

# QR "T:" values that phones usually accept: WPA, WEP, nopass
AUTH_TO_T_VALUE = {
    "Open / None": "nopass",
    "WEP (Legacy / Insecure)": "WEP",
    "WPA/WPA2-Personal (PSK)": "WPA",
    "WPA2-Personal (PSK)": "WPA",
    "WPA3-Personal (SAE)": "WPA",            # fallback for phone QR parsing
    "WPA2/WPA3-Personal (Mixed)": "WPA",      # fallback for phone QR parsing
}

AUTH_WARNINGS = {
    "WEP (Legacy / Insecure)": "Warning: WEP is legacy and insecure. Use WPA2/WPA3 when possible.",
    "WPA3-Personal (SAE)": "Note: Many phones expect T:WPA in Wi-Fi QR codes. This app encodes WPA3 as T:WPA for compatibility.",
    "WPA2/WPA3-Personal (Mixed)": "Note: Mixed WPA2/WPA3 is encoded as T:WPA for broad compatibility.",
}

ECC_HELP_TEXT = (
    "QR Error Correction:\n"
    "L ≈ 7% recovery (smallest)\n"
    "M ≈ 15% recovery (recommended)\n"
    "Q ≈ 25% recovery\n"
    "H ≈ 30% recovery (most tolerant)\n\n"
    "Higher levels increase redundancy (better if damaged), but make the QR denser."
)


# -----------------------------
# Crash logging
# -----------------------------
def get_crashlog_path() -> Path:
    base = Path.home() / ".wifi_qr_generator_logs"
    base.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return base / f"crash_{TAG_TEXT}_{ts}.log"


def write_crash_log(exc_type, exc_value, exc_tb) -> Path:
    log_path = get_crashlog_path()
    try:
        with log_path.open("w", encoding="utf-8") as f:
            f.write(f"{APP_TITLE} Crash Log\n")
            f.write(f"Tag: {TAG_TEXT}\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"Platform: {platform.platform()}\n")
            f.write(f"Python: {sys.version}\n")
            f.write(f"Executable: {sys.executable}\n")
            f.write(f"CWD: {os.getcwd()}\n\n")
            f.write("Exception:\n")
            f.write("".join(traceback.format_exception(exc_type, exc_value, exc_tb)))
    except Exception:
        pass
    return log_path


def global_excepthook(exc_type, exc_value, exc_tb):
    log_path = write_crash_log(exc_type, exc_value, exc_tb)
    try:
        r = tk.Tk()
        r.withdraw()
        messagebox.showerror(
            APP_TITLE,
            "The application crashed.\n\n"
            f"A crash log was written to:\n{log_path}\n\n"
            "Please share that file for troubleshooting.",
        )
        r.destroy()
    except Exception:
        sys.stderr.write(f"{APP_TITLE} crashed. Crash log written to: {log_path}\n")


sys.excepthook = global_excepthook


def get_profiles_path() -> Path:
    return Path.home() / ".wifi_qr_generator_profiles.json"


def safe_read_json(path: Path) -> Dict[str, Any]:
    try:
        if not path.exists():
            return {"profiles": []}
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"profiles": []}
        if "profiles" not in data or not isinstance(data["profiles"], list):
            data["profiles"] = []
        return data
    except Exception:
        return {"profiles": []}


def safe_write_json(path: Path, data: Dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        tmp.replace(path)
    except Exception:
        pass


def escape_wifi_field(value: str) -> str:
    """
    Escape special characters per common Wi-Fi QR conventions:
    backslash, semicolon, comma, colon are escaped with backslash.
    """
    if value is None:
        return ""
    v = value.replace("\\", "\\\\")
    v = v.replace(";", r"\;")
    v = v.replace(",", r"\,")
    v = v.replace(":", r"\:")
    return v


def ecc_from_letter(letter: str) -> int:
    letter = (letter or "M").upper().strip()
    return {
        "L": ERROR_CORRECT_L,
        "M": ERROR_CORRECT_M,
        "Q": ERROR_CORRECT_Q,
        "H": ERROR_CORRECT_H,
    }.get(letter, ERROR_CORRECT_M)


@dataclass
class Profile:
    name: str
    ssid: str
    auth: str
    hidden: bool
    dpi: int
    ecc: str
    border: int
    size_mode: str
    inches: float
    px_size: int
    dark_mode: str


class WiFiQRApp:
    def __init__(self) -> None:
        self.root = self._create_root()
        self.root.title(APP_TITLE)
        self.root.minsize(900, 600)
        self.root.geometry(f"{DEFAULT_W}x{DEFAULT_H}")
        try:
            self.root.resizable(True, True)
        except Exception:
            pass

        self.current_qr_pil: Optional[Image.Image] = None
        self.current_payload: str = ""

        # Used only for preview display
        self._ctk_preview_image_obj = None  # CTkImage reference holder
        self._tk_preview_image_obj = None   # PhotoImage reference holder

        self.profiles_path = get_profiles_path()
        self.profiles: List[Profile] = self._load_profiles()

        self._build_ui()
        self._refresh_profiles_dropdown()
        self._update_warning_label()

    def _create_root(self):
        if USE_CTK:
            ctk.set_default_color_theme("blue")
            ctk.set_appearance_mode("Dark")
            return ctk.CTk()
        return tk.Tk()

    def _frame_or_labelframe(self, parent, *, label_text: Optional[str] = None):
        if USE_CTK:
            return ctk.CTkFrame(parent, corner_radius=12)
        return tk.LabelFrame(parent, text=label_text or "")

    def _build_ui(self) -> None:
        if USE_CTK:
            self.main = ctk.CTkFrame(self.root, corner_radius=12)
            self.main.pack(fill="both", expand=True, padx=14, pady=14)
        else:
            self.main = tk.Frame(self.root)
            self.main.pack(fill="both", expand=True, padx=10, pady=10)

        if USE_CTK:
            self.main.columnconfigure(0, weight=1)
            self.main.columnconfigure(1, weight=1)
            self.main.rowconfigure(0, weight=1)
        else:
            self.main.grid_columnconfigure(0, weight=1)
            self.main.grid_columnconfigure(1, weight=1)
            self.main.grid_rowconfigure(0, weight=1)

        self.left = self._frame_or_labelframe(self.main, label_text="Inputs")
        self.right = self._frame_or_labelframe(self.main, label_text="Preview")

        if USE_CTK:
            self.left.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=0)
            self.right.grid(row=0, column=1, sticky="nsew", padx=(10, 0), pady=0)
            self.left.columnconfigure(0, weight=1)
            self.right.columnconfigure(0, weight=1)
            self.right.rowconfigure(0, weight=1)
        else:
            self.left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
            self.right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
            self.left.grid_columnconfigure(0, weight=1)
            self.right.grid_columnconfigure(0, weight=1)
            self.right.grid_rowconfigure(0, weight=1)

        # Header row
        if USE_CTK:
            header = ctk.CTkFrame(self.left, fg_color="transparent")
            header.grid(row=0, column=0, sticky="ew", padx=14, pady=(14, 8))
            header.columnconfigure(0, weight=1)
            header.columnconfigure(1, weight=0)
        else:
            header = tk.Frame(self.left)
            header.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 6))
            header.grid_columnconfigure(0, weight=1)

        # Profiles dropdown
        if USE_CTK:
            self.profile_var = tk.StringVar(value="Recent Profiles (Load)")
            self.profile_menu = ctk.CTkOptionMenu(
                header,
                variable=self.profile_var,
                values=["Recent Profiles (Load)"],
                command=self.on_profile_select,
                width=260,
            )
            self.profile_menu.grid(row=0, column=0, sticky="w")
        else:
            self.profile_var = tk.StringVar(value="Recent Profiles (Load)")
            self.profile_menu = tk.OptionMenu(header, self.profile_var, "Recent Profiles (Load)", command=self.on_profile_select)
            self.profile_menu.grid(row=0, column=0, sticky="w")

        # Dark mode toggle
        if USE_CTK:
            self.appearance_var = tk.StringVar(value="Dark")
            self.appearance_menu = ctk.CTkOptionMenu(
                header,
                variable=self.appearance_var,
                values=["Dark", "Light"],
                command=self.on_appearance_change,
                width=120,
            )
            self.appearance_menu.grid(row=0, column=1, sticky="e")
        else:
            self.appearance_var = tk.StringVar(value="Light")
            tk.Label(header, text="Theme:").grid(row=0, column=1, sticky="e", padx=(10, 4))
            self.appearance_menu = tk.OptionMenu(header, self.appearance_var, "Light", "Dark", command=self.on_appearance_change)
            self.appearance_menu.grid(row=0, column=2, sticky="e")

        # Form
        if USE_CTK:
            form = ctk.CTkFrame(self.left, corner_radius=12)
            form.grid(row=1, column=0, sticky="ew", padx=14, pady=8)
            form.columnconfigure(0, weight=1)
        else:
            form = tk.Frame(self.left)
            form.grid(row=1, column=0, sticky="ew", padx=10, pady=6)
            form.grid_columnconfigure(0, weight=1)

        self._add_label(form, "SSID")
        self.ssid_var = tk.StringVar()
        self.ssid_entry = self._make_entry(form, self.ssid_var, show=None)
        self._bind_live_update(self.ssid_entry)

        self._add_label(form, "Password")
        self.pass_var = tk.StringVar()
        self.pass_entry = self._make_entry(form, self.pass_var, show="*")
        self._bind_live_update(self.pass_entry)

        self.show_pass_var = tk.BooleanVar(value=False)
        if USE_CTK:
            self.show_pass_cb = ctk.CTkCheckBox(form, text="Show password", variable=self.show_pass_var, command=self.on_toggle_show_password)
            self.show_pass_cb.grid(row=form.grid_size()[1], column=0, sticky="w", pady=(6, 6))
        else:
            self.show_pass_cb = tk.Checkbutton(form, text="Show password", variable=self.show_pass_var, command=self.on_toggle_show_password)
            self.show_pass_cb.grid(row=form.grid_size()[1], column=0, sticky="w", pady=(4, 4))
        self._bind_live_update(self.show_pass_cb)

        self._add_label(form, "Encryption / Authentication")
        self.auth_var = tk.StringVar(value=AUTH_OPTIONS[2])
        if USE_CTK:
            self.auth_menu = ctk.CTkOptionMenu(form, variable=self.auth_var, values=AUTH_OPTIONS, command=lambda _=None: self.on_auth_change())
            self.auth_menu.grid(row=form.grid_size()[1], column=0, sticky="ew", pady=(0, 6))
        else:
            self.auth_menu = tk.OptionMenu(form, self.auth_var, *AUTH_OPTIONS, command=lambda _=None: self.on_auth_change())
            self.auth_menu.grid(row=form.grid_size()[1], column=0, sticky="ew", pady=(0, 6))
        self._bind_live_update(self.auth_menu)

        self.hidden_var = tk.BooleanVar(value=False)
        if USE_CTK:
            self.hidden_cb = ctk.CTkCheckBox(form, text="Hidden SSID", variable=self.hidden_var)
            self.hidden_cb.grid(row=form.grid_size()[1], column=0, sticky="w", pady=(4, 4))
        else:
            self.hidden_cb = tk.Checkbutton(form, text="Hidden SSID", variable=self.hidden_var)
            self.hidden_cb.grid(row=form.grid_size()[1], column=0, sticky="w", pady=(4, 4))
        self._bind_live_update(self.hidden_cb)

        if USE_CTK:
            self.warn_label = ctk.CTkLabel(form, text="", text_color=("gray20", "gray80"), wraplength=420, justify="left")
            self.warn_label.grid(row=form.grid_size()[1], column=0, sticky="ew", pady=(6, 2))
        else:
            self.warn_label = tk.Label(form, text="", fg="gray25", wraplength=420, justify="left")
            self.warn_label.grid(row=form.grid_size()[1], column=0, sticky="ew", pady=(6, 2))

        # Buttons row (added Clear Recent Profiles)
        if USE_CTK:
            btns = ctk.CTkFrame(self.left, fg_color="transparent")
            btns.grid(row=2, column=0, sticky="ew", padx=14, pady=(6, 8))
            btns.columnconfigure((0, 1, 2, 3), weight=1)

            self.generate_btn = ctk.CTkButton(btns, text="Generate / Update QR", command=self.on_generate)
            self.generate_btn.grid(row=0, column=0, sticky="ew", padx=(0, 8))

            self.clear_btn = ctk.CTkButton(btns, text="Clear / Reset", command=self.on_clear)
            self.clear_btn.grid(row=0, column=1, sticky="ew", padx=(0, 8))

            self.save_profile_btn = ctk.CTkButton(btns, text="Save to Recent", command=self.on_save_profile)
            self.save_profile_btn.grid(row=0, column=2, sticky="ew", padx=(0, 8))

            self.clear_profiles_btn = ctk.CTkButton(btns, text="Clear Recent Profiles", command=self.on_clear_profiles)
            self.clear_profiles_btn.grid(row=0, column=3, sticky="ew")
        else:
            btns = tk.Frame(self.left)
            btns.grid(row=2, column=0, sticky="ew", padx=10, pady=(6, 8))
            btns.grid_columnconfigure((0, 1, 2, 3), weight=1)

            self.generate_btn = tk.Button(btns, text="Generate / Update QR", command=self.on_generate)
            self.generate_btn.grid(row=0, column=0, sticky="ew", padx=(0, 6))

            self.clear_btn = tk.Button(btns, text="Clear / Reset", command=self.on_clear)
            self.clear_btn.grid(row=0, column=1, sticky="ew", padx=(0, 6))

            self.save_profile_btn = tk.Button(btns, text="Save to Recent", command=self.on_save_profile)
            self.save_profile_btn.grid(row=0, column=2, sticky="ew", padx=(0, 6))

            self.clear_profiles_btn = tk.Button(btns, text="Clear Recent Profiles", command=self.on_clear_profiles)
            self.clear_profiles_btn.grid(row=0, column=3, sticky="ew")

        # Export / Clipboard row
        if USE_CTK:
            xrow = ctk.CTkFrame(self.left, fg_color="transparent")
            xrow.grid(row=3, column=0, sticky="ew", padx=14, pady=(0, 8))
            xrow.columnconfigure((0, 1, 2, 3), weight=1)
            self.png_btn = ctk.CTkButton(xrow, text="Export PNG", command=self.on_export_png)
            self.png_btn.grid(row=0, column=0, sticky="ew", padx=(0, 8))
            self.svg_btn = ctk.CTkButton(xrow, text="Export SVG", command=self.on_export_svg)
            self.svg_btn.grid(row=0, column=1, sticky="ew", padx=(0, 8))
            self.copy_img_btn = ctk.CTkButton(xrow, text="Copy QR Image", command=self.on_copy_image)
            self.copy_img_btn.grid(row=0, column=2, sticky="ew", padx=(0, 8))
            self.copy_payload_btn = ctk.CTkButton(xrow, text="Copy Payload Text", command=self.on_copy_payload)
            self.copy_payload_btn.grid(row=0, column=3, sticky="ew")
        else:
            xrow = tk.Frame(self.left)
            xrow.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 8))
            xrow.grid_columnconfigure((0, 1, 2, 3), weight=1)
            self.png_btn = tk.Button(xrow, text="Export PNG", command=self.on_export_png)
            self.png_btn.grid(row=0, column=0, sticky="ew", padx=(0, 6))
            self.svg_btn = tk.Button(xrow, text="Export SVG", command=self.on_export_svg)
            self.svg_btn.grid(row=0, column=1, sticky="ew", padx=(0, 6))
            self.copy_img_btn = tk.Button(xrow, text="Copy QR Image", command=self.on_copy_image)
            self.copy_img_btn.grid(row=0, column=2, sticky="ew", padx=(0, 6))
            self.copy_payload_btn = tk.Button(xrow, text="Copy Payload Text", command=self.on_copy_payload)
            self.copy_payload_btn.grid(row=0, column=3, sticky="ew")

        # Advanced (collapsible)
        if USE_CTK:
            adv_header = ctk.CTkFrame(self.left, fg_color="transparent")
            adv_header.grid(row=4, column=0, sticky="ew", padx=14, pady=(0, 6))
            adv_header.columnconfigure(0, weight=1)
            self.adv_open = tk.BooleanVar(value=False)
            self.adv_btn = ctk.CTkButton(adv_header, text="Show Advanced Options", command=self.on_toggle_advanced)
            self.adv_btn.grid(row=0, column=0, sticky="ew")
            self.adv_frame = ctk.CTkFrame(self.left, corner_radius=12)
            self.adv_frame.grid(row=5, column=0, sticky="ew", padx=14, pady=(0, 8))
            self.adv_frame.grid_remove()
            self._build_advanced(self.adv_frame)
        else:
            adv_header = tk.Frame(self.left)
            adv_header.grid(row=4, column=0, sticky="ew", padx=10, pady=(0, 6))
            self.adv_open = tk.BooleanVar(value=False)
            self.adv_btn = tk.Button(adv_header, text="Show Advanced Options", command=self.on_toggle_advanced)
            self.adv_btn.grid(row=0, column=0, sticky="ew")
            self.adv_frame = tk.Frame(self.left)
            self.adv_frame.grid(row=5, column=0, sticky="ew", padx=10, pady=(0, 8))
            self.adv_frame.grid_remove()
            self._build_advanced(self.adv_frame)

        # Raw payload box
        if USE_CTK:
            payload_frame = ctk.CTkFrame(self.left, corner_radius=12)
            payload_frame.grid(row=6, column=0, sticky="nsew", padx=14, pady=(0, 6))
            payload_frame.columnconfigure(0, weight=1)
            ctk.CTkLabel(payload_frame, text="Raw Wi-Fi Payload (read-only)").grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))
            self.payload_text = ctk.CTkTextbox(payload_frame, height=84, wrap="word")
            self.payload_text.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 10))
            self.payload_text.configure(state="disabled")
        else:
            payload_frame = tk.LabelFrame(self.left, text="Raw Wi-Fi Payload (read-only)")
            payload_frame.grid(row=6, column=0, sticky="ew", padx=10, pady=(0, 6))
            self.payload_text = tk.Text(payload_frame, height=4, wrap="word")
            self.payload_text.pack(fill="x", padx=8, pady=8)
            self.payload_text.configure(state="disabled")

        # Footer tag (visible)
        if USE_CTK:
            footer = ctk.CTkLabel(self.left, text=TAG_TEXT, text_color=("gray40", "gray60"))
            footer.grid(row=7, column=0, sticky="w", padx=14, pady=(0, 12))
        else:
            footer = tk.Label(self.left, text=TAG_TEXT, fg="gray40")
            footer.grid(row=7, column=0, sticky="w", padx=10, pady=(0, 10))

        # Right pane: preview area
        if USE_CTK:
            preview_outer = ctk.CTkFrame(self.right, corner_radius=12)
            preview_outer.grid(row=0, column=0, sticky="nsew", padx=14, pady=14)
            preview_outer.columnconfigure(0, weight=1)
            preview_outer.rowconfigure(1, weight=1)

            ctk.CTkLabel(preview_outer, text="QR Preview").grid(row=0, column=0, sticky="w", padx=12, pady=(12, 6))

            self.preview_label = ctk.CTkLabel(preview_outer, text="(Generate to preview)", width=600, height=600)
            self.preview_label.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        else:
            preview_outer = tk.Frame(self.right)
            preview_outer.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
            preview_outer.grid_columnconfigure(0, weight=1)
            preview_outer.grid_rowconfigure(1, weight=1)
            tk.Label(preview_outer, text="QR Preview").grid(row=0, column=0, sticky="w", pady=(0, 6))
            self.preview_label = tk.Label(preview_outer, text="(Generate to preview)")
            self.preview_label.grid(row=1, column=0, sticky="nsew")

    def _add_label(self, parent, text: str) -> None:
        if USE_CTK:
            ctk.CTkLabel(parent, text=text).grid(row=parent.grid_size()[1], column=0, sticky="w", pady=(8, 4))
        else:
            tk.Label(parent, text=text).grid(row=parent.grid_size()[1], column=0, sticky="w", pady=(6, 3))

    def _make_entry(self, parent, var: tk.StringVar, show: Optional[str]):
        if USE_CTK:
            e = ctk.CTkEntry(parent, textvariable=var, show=show if show else "")
            e.grid(row=parent.grid_size()[1], column=0, sticky="ew", pady=(0, 6))
            return e
        e = tk.Entry(parent, textvariable=var, show=show if show else "")
        e.grid(row=parent.grid_size()[1], column=0, sticky="ew", pady=(0, 6))
        return e

    def _bind_live_update(self, widget) -> None:
        try:
            widget.bind("<KeyRelease>", lambda _e: self._maybe_autoupdate())
        except Exception:
            pass

    # -----------------------------
    # Core functions
    # -----------------------------
    def build_wifi_payload(self, ssid: str, password: str, auth: str, hidden: bool) -> str:
        ssid_esc = escape_wifi_field(ssid)
        pass_esc = escape_wifi_field(password)
        t_val = AUTH_TO_T_VALUE.get(auth, "WPA")

        parts = [f"WIFI:T:{t_val};", f"S:{ssid_esc};"]
        if t_val != "nopass":
            parts.append(f"P:{pass_esc};")
        parts.append(f"H:{'true' if hidden else 'false'};;")
        return "".join(parts)

    def generate_qr_image(self, payload: str, ecc_letter: str, border: int, target_px: int) -> Image.Image:
        qr = qrcode.QRCode(
            version=None,
            error_correction=ecc_from_letter(ecc_letter),
            box_size=10,
            border=max(0, int(border)),
        )
        qr.add_data(payload)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        pil = img.convert("RGB")
        if target_px and target_px > 0:
            pil = pil.resize((target_px, target_px), resample=Image.NEAREST)
        return pil

    def export_png(self, img: Image.Image, path: str, dpi: int) -> None:
        img.save(path, format="PNG", dpi=(dpi, dpi))

    def export_svg(self, payload: str, ecc_letter: str, border: int, path: str) -> None:
        if not HAS_SVG:
            raise RuntimeError("SVG support is unavailable (qrcode.image.svg could not be imported).")
        factory = qrcode.image.svg.SvgImage
        qr = qrcode.QRCode(
            version=None,
            error_correction=ecc_from_letter(ecc_letter),
            box_size=10,
            border=max(0, int(border)),
        )
        qr.add_data(payload)
        qr.make(fit=True)
        svg_img = qr.make_image(image_factory=factory)
        data = svg_img.to_string()
        with open(path, "wb") as f:
            f.write(data)

    def copy_to_clipboard(self) -> None:
        if self.current_qr_pil is None:
            messagebox.showinfo(APP_TITLE, "No QR image available. Please generate a QR code first.")
            return

        if platform.system().lower().startswith("win"):
            try:
                import win32clipboard  # type: ignore
                from io import BytesIO

                output = BytesIO()
                bmp = self.current_qr_pil.convert("RGB")
                bmp.save(output, "BMP")
                data = output.getvalue()[14:]  # DIB data
                output.close()

                win32clipboard.OpenClipboard()
                win32clipboard.EmptyClipboard()
                win32clipboard.SetClipboardData(win32clipboard.CF_DIB, data)
                win32clipboard.CloseClipboard()

                messagebox.showinfo(APP_TITLE, "QR image copied to clipboard.")
                return
            except Exception:
                pass

        self._copy_text_to_clipboard(self.current_payload)
        messagebox.showinfo(
            APP_TITLE,
            "Image clipboard copy is not available on this OS/configuration.\n\n"
            "The Wi-Fi payload text was copied to your clipboard instead.\n"
            "Tip: You can still export PNG/SVG for sharing.",
        )

    # -----------------------------
    # Helpers / behavior
    # -----------------------------
    def _copy_text_to_clipboard(self, text: str) -> None:
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()
        except Exception:
            pass

    def _set_payload_textbox(self, payload: str) -> None:
        if USE_CTK:
            self.payload_text.configure(state="normal")
            self.payload_text.delete("1.0", "end")
            self.payload_text.insert("1.0", payload)
            self.payload_text.configure(state="disabled")
        else:
            self.payload_text.configure(state="normal")
            self.payload_text.delete("1.0", "end")
            self.payload_text.insert("1.0", payload)
            self.payload_text.configure(state="disabled")

    def _set_preview_image(self, pil_img: Image.Image) -> None:
        # Larger window now, so allow a slightly larger preview
        preview_max = 600
        img = pil_img.copy()
        img.thumbnail((preview_max, preview_max), resample=Image.NEAREST)

        if USE_CTK:
            # FIX: Use CTkImage for proper HiDPI scaling and to remove the warning
            self._ctk_preview_image_obj = ctk.CTkImage(light_image=img, dark_image=img, size=img.size)
            self.preview_label.configure(image=self._ctk_preview_image_obj, text="")
        else:
            self._tk_preview_image_obj = ImageTk.PhotoImage(img)
            self.preview_label.configure(image=self._tk_preview_image_obj, text="")
            self.preview_label.image = self._tk_preview_image_obj

    def _parse_int(self, value: str, default: int, min_v: int = 1, max_v: int = 100000) -> int:
        try:
            v = int(str(value).strip())
            return max(min_v, min(max_v, v))
        except Exception:
            return default

    def _parse_float(self, value: str, default: float, min_v: float = 0.1, max_v: float = 1000.0) -> float:
        try:
            v = float(str(value).strip())
            return max(min_v, min(max_v, v))
        except Exception:
            return default

    def _compute_target_px_and_dpi(self) -> Tuple[int, int, float, str]:
        size_mode = getattr(self, "size_mode_var", tk.StringVar(value="inches")).get()
        preset = getattr(self, "preset_var", tk.StringVar(value="2x2 in @ 300 DPI (Default)")).get()

        if preset == "2x2 in @ 300 DPI (Default)":
            dpi = 300
            inches = DEFAULT_INCHES
            return int(round(inches * dpi)), dpi, inches, "inches"
        if preset == "2x2 in @ 600 DPI":
            dpi = 600
            inches = DEFAULT_INCHES
            return int(round(inches * dpi)), dpi, inches, "inches"

        dpi = self._parse_int(getattr(self, "dpi_var", tk.StringVar(value=str(DEFAULT_DPI))).get(), DEFAULT_DPI, 72, 2400)
        inches = self._parse_float(getattr(self, "inches_var", tk.StringVar(value=str(DEFAULT_INCHES))).get(), DEFAULT_INCHES, 0.5, 20.0)
        px_size = self._parse_int(getattr(self, "px_var", tk.StringVar(value="600")).get(), 600, 128, 10000)

        if size_mode == "pixels":
            return px_size, dpi, inches, "pixels"
        return int(round(inches * dpi)), dpi, inches, "inches"

    def _update_warning_label(self) -> None:
        auth = self.auth_var.get()
        warning = AUTH_WARNINGS.get(auth, "")
        self.warn_label.configure(text=warning if warning else "")

    def on_toggle_show_password(self) -> None:
        show = "" if self.show_pass_var.get() else "*"
        try:
            self.pass_entry.configure(show=show)
        except Exception:
            try:
                self.pass_entry.config(show=show)
            except Exception:
                pass
        self._maybe_autoupdate()

    def on_auth_change(self) -> None:
        self._update_warning_label()
        self._maybe_autoupdate()

    def on_appearance_change(self, _value: Optional[str] = None) -> None:
        if USE_CTK:
            ctk.set_appearance_mode(self.appearance_var.get())
        self._maybe_autoupdate()

    def on_toggle_advanced(self) -> None:
        is_open = self.adv_open.get()
        if not is_open:
            self.adv_open.set(True)
            self.adv_frame.grid()
            self.adv_btn.configure(text="Hide Advanced Options")
        else:
            self.adv_open.set(False)
            self.adv_frame.grid_remove()
            self.adv_btn.configure(text="Show Advanced Options")

    def on_preset_change(self) -> None:
        preset = self.preset_var.get()
        if preset == "2x2 in @ 300 DPI (Default)":
            self.size_mode_var.set("inches")
            self.dpi_var.set("300")
            self.inches_var.set(str(DEFAULT_INCHES))
            self.px_var.set("600")
        elif preset == "2x2 in @ 600 DPI":
            self.size_mode_var.set("inches")
            self.dpi_var.set("600")
            self.inches_var.set(str(DEFAULT_INCHES))
            self.px_var.set("1200")
        self._maybe_autoupdate()

    def _maybe_autoupdate(self) -> None:
        try:
            if hasattr(self, "autoupdate_var") and self.autoupdate_var.get():
                self._generate_and_render(show_warnings=False)
        except Exception:
            pass

    def _validate_inputs(self, ssid: str, password: str, auth: str) -> bool:
        if ssid == "":
            if not messagebox.askyesno(APP_TITLE, "SSID is empty.\n\nContinue anyway?"):
                return False

        if ssid != ssid.strip():
            if not messagebox.askyesno(APP_TITLE, "SSID has leading/trailing spaces.\n\nContinue anyway?"):
                return False

        t_val = AUTH_TO_T_VALUE.get(auth, "WPA")
        if t_val == "nopass":
            if password.strip() != "":
                messagebox.showerror(APP_TITLE, "Open / None selected: Password must be blank.")
                return False
        else:
            if password.strip() == "":
                messagebox.showerror(APP_TITLE, "A password is required for WPA/WEP networks.")
                return False

        if auth == "WEP (Legacy / Insecure)":
            messagebox.showwarning(APP_TITLE, AUTH_WARNINGS.get(auth, "WEP is insecure."))

        return True

    def on_generate(self) -> None:
        self._generate_and_render(show_warnings=True)
        if self.current_payload:
            self._save_current_profile_to_recent()

    def _generate_and_render(self, show_warnings: bool) -> None:
        ssid = self.ssid_var.get()
        password = self.pass_var.get()
        auth = self.auth_var.get()
        hidden = bool(self.hidden_var.get())

        if show_warnings:
            if not self._validate_inputs(ssid, password, auth):
                return

        payload = self.build_wifi_payload(ssid=ssid, password=password, auth=auth, hidden=hidden)
        self.current_payload = payload
        self._set_payload_textbox(payload)

        ecc = getattr(self, "ecc_var", tk.StringVar(value=DEFAULT_ECC)).get()
        border = self._parse_int(getattr(self, "border_var", tk.StringVar(value=str(DEFAULT_BORDER))).get(), DEFAULT_BORDER, 0, 20)
        target_px, _dpi, _inches, _mode = self._compute_target_px_and_dpi()

        pil = self.generate_qr_image(payload=payload, ecc_letter=ecc, border=border, target_px=target_px)
        self.current_qr_pil = pil
        self._set_preview_image(pil)
        self._update_warning_label()

    def on_export_png(self) -> None:
        if self.current_qr_pil is None:
            messagebox.showinfo(APP_TITLE, "No QR image available. Please generate a QR code first.")
            return

        target_px, dpi, _inches, _mode = self._compute_target_px_and_dpi()
        path = filedialog.asksaveasfilename(
            title="Export PNG",
            defaultextension=".png",
            initialfile="wifi_qr.png",
            filetypes=[("PNG Image", "*.png")],
        )
        if not path:
            return

        img = self.current_qr_pil
        if img.size != (target_px, target_px):
            img = img.resize((target_px, target_px), resample=Image.NEAREST)
        self.export_png(img, path, dpi=dpi)
        messagebox.showinfo(APP_TITLE, f"Exported PNG:\n{path}")

    def on_export_svg(self) -> None:
        if not self.current_payload:
            messagebox.showinfo(APP_TITLE, "No payload available. Please generate a QR code first.")
            return

        if not HAS_SVG:
            messagebox.showerror(APP_TITLE, "SVG export is unavailable (qrcode.image.svg import failed).")
            return

        path = filedialog.asksaveasfilename(
            title="Export SVG",
            defaultextension=".svg",
            initialfile="wifi_qr.svg",
            filetypes=[("SVG Image", "*.svg")],
        )
        if not path:
            return

        ecc = getattr(self, "ecc_var", tk.StringVar(value=DEFAULT_ECC)).get()
        border = self._parse_int(getattr(self, "border_var", tk.StringVar(value=str(DEFAULT_BORDER))).get(), DEFAULT_BORDER, 0, 20)

        self.export_svg(payload=self.current_payload, ecc_letter=ecc, border=border, path=path)
        messagebox.showinfo(APP_TITLE, f"Exported SVG:\n{path}")

    def on_copy_image(self) -> None:
        self.copy_to_clipboard()

    def on_copy_payload(self) -> None:
        if not self.current_payload:
            messagebox.showinfo(APP_TITLE, "No payload available. Please generate a QR code first.")
            return
        self._copy_text_to_clipboard(self.current_payload)
        messagebox.showinfo(APP_TITLE, "Wi-Fi payload text copied to clipboard.")

    def on_clear(self) -> None:
        self.ssid_var.set("")
        self.pass_var.set("")
        self.auth_var.set(AUTH_OPTIONS[2])
        self.hidden_var.set(False)
        self.show_pass_var.set(False)
        self.on_toggle_show_password()

        if hasattr(self, "preset_var"):
            self.preset_var.set("2x2 in @ 300 DPI (Default)")
            self.size_mode_var.set("inches")
            self.dpi_var.set(str(DEFAULT_DPI))
            self.inches_var.set(str(DEFAULT_INCHES))
            self.px_var.set("600")
            self.ecc_var.set(DEFAULT_ECC)
            self.border_var.set(str(DEFAULT_BORDER))
            self.autoupdate_var.set(False)

        self.current_qr_pil = None
        self.current_payload = ""
        self._set_payload_textbox("")
        if USE_CTK:
            self.preview_label.configure(image=None, text="(Generate to preview)")
            self._ctk_preview_image_obj = None
        else:
            self.preview_label.configure(image="", text="(Generate to preview)")
            self._tk_preview_image_obj = None
        self._update_warning_label()

    def on_clear_profiles(self) -> None:
        if not messagebox.askyesno(APP_TITLE, "Clear all recent profiles?\n\nThis will remove saved entries from disk."):
            return
        self.profiles = []
        try:
            if self.profiles_path.exists():
                self.profiles_path.unlink()
        except Exception:
            # If delete fails, still clear in-memory and persist empty list
            pass
        self._persist_profiles()
        self.profile_var.set("Recent Profiles (Load)")
        self._refresh_profiles_dropdown()
        messagebox.showinfo(APP_TITLE, "Recent profiles cleared.")

    # -----------------------------
    # Advanced UI
    # -----------------------------
    def _build_advanced(self, parent) -> None:
        if USE_CTK:
            parent.columnconfigure(0, weight=1)
            grid_padx = 12
            grid_pady = 8
        else:
            parent.grid_columnconfigure(0, weight=1)
            grid_padx = 8
            grid_pady = 6

        if USE_CTK:
            ctk.CTkLabel(parent, text="Export Preset").grid(row=0, column=0, sticky="w", padx=grid_padx, pady=(12, 4))
            self.preset_var = tk.StringVar(value="2x2 in @ 300 DPI (Default)")
            self.preset_menu = ctk.CTkOptionMenu(
                parent,
                variable=self.preset_var,
                values=["2x2 in @ 300 DPI (Default)", "2x2 in @ 600 DPI", "Custom (Advanced)"],
                command=lambda _v: self.on_preset_change(),
            )
            self.preset_menu.grid(row=1, column=0, sticky="ew", padx=grid_padx, pady=(0, grid_pady))
        else:
            tk.Label(parent, text="Export Preset").grid(row=0, column=0, sticky="w", padx=grid_padx, pady=(10, 3))
            self.preset_var = tk.StringVar(value="2x2 in @ 300 DPI (Default)")
            self.preset_menu = tk.OptionMenu(
                parent,
                self.preset_var,
                "2x2 in @ 300 DPI (Default)",
                "2x2 in @ 600 DPI",
                "Custom (Advanced)",
                command=lambda _v: self.on_preset_change(),
            )
            self.preset_menu.grid(row=1, column=0, sticky="ew", padx=grid_padx, pady=(0, grid_pady))

        if USE_CTK:
            self.size_mode_var = tk.StringVar(value="inches")
            mode_frame = ctk.CTkFrame(parent, fg_color="transparent")
            mode_frame.grid(row=2, column=0, sticky="ew", padx=grid_padx, pady=(0, grid_pady))
            mode_frame.columnconfigure((0, 1), weight=1)
            ctk.CTkRadioButton(mode_frame, text="Inches + DPI", variable=self.size_mode_var, value="inches", command=self._maybe_autoupdate).grid(row=0, column=0, sticky="w")
            ctk.CTkRadioButton(mode_frame, text="Pixels (square)", variable=self.size_mode_var, value="pixels", command=self._maybe_autoupdate).grid(row=0, column=1, sticky="w")
        else:
            self.size_mode_var = tk.StringVar(value="inches")
            mode_frame = tk.Frame(parent)
            mode_frame.grid(row=2, column=0, sticky="ew", padx=grid_padx, pady=(0, grid_pady))
            tk.Radiobutton(mode_frame, text="Inches + DPI", variable=self.size_mode_var, value="inches", command=self._maybe_autoupdate).pack(side="left")
            tk.Radiobutton(mode_frame, text="Pixels (square)", variable=self.size_mode_var, value="pixels", command=self._maybe_autoupdate).pack(side="left", padx=8)

        if USE_CTK:
            ctk.CTkLabel(parent, text="DPI").grid(row=3, column=0, sticky="w", padx=grid_padx, pady=(0, 4))
            self.dpi_var = tk.StringVar(value=str(DEFAULT_DPI))
            self.dpi_entry = ctk.CTkEntry(parent, textvariable=self.dpi_var)
            self.dpi_entry.grid(row=4, column=0, sticky="ew", padx=grid_padx, pady=(0, grid_pady))
        else:
            tk.Label(parent, text="DPI").grid(row=3, column=0, sticky="w", padx=grid_padx, pady=(0, 3))
            self.dpi_var = tk.StringVar(value=str(DEFAULT_DPI))
            self.dpi_entry = tk.Entry(parent, textvariable=self.dpi_var)
            self.dpi_entry.grid(row=4, column=0, sticky="ew", padx=grid_padx, pady=(0, grid_pady))

        if USE_CTK:
            ctk.CTkLabel(parent, text="Size (inches, square)").grid(row=5, column=0, sticky="w", padx=grid_padx, pady=(0, 4))
            self.inches_var = tk.StringVar(value=str(DEFAULT_INCHES))
            self.inches_entry = ctk.CTkEntry(parent, textvariable=self.inches_var)
            self.inches_entry.grid(row=6, column=0, sticky="ew", padx=grid_padx, pady=(0, grid_pady))
        else:
            tk.Label(parent, text="Size (inches, square)").grid(row=5, column=0, sticky="w", padx=grid_padx, pady=(0, 3))
            self.inches_var = tk.StringVar(value=str(DEFAULT_INCHES))
            self.inches_entry = tk.Entry(parent, textvariable=self.inches_var)
            self.inches_entry.grid(row=6, column=0, sticky="ew", padx=grid_padx, pady=(0, grid_pady))

        if USE_CTK:
            ctk.CTkLabel(parent, text="Pixel size (square, px)").grid(row=7, column=0, sticky="w", padx=grid_padx, pady=(0, 4))
            self.px_var = tk.StringVar(value="600")
            self.px_entry = ctk.CTkEntry(parent, textvariable=self.px_var)
            self.px_entry.grid(row=8, column=0, sticky="ew", padx=grid_padx, pady=(0, grid_pady))
        else:
            tk.Label(parent, text="Pixel size (square, px)").grid(row=7, column=0, sticky="w", padx=grid_padx, pady=(0, 3))
            self.px_var = tk.StringVar(value="600")
            self.px_entry = tk.Entry(parent, textvariable=self.px_var)
            self.px_entry.grid(row=8, column=0, sticky="ew", padx=grid_padx, pady=(0, grid_pady))

        if USE_CTK:
            ctk.CTkLabel(parent, text="QR Error Correction").grid(row=9, column=0, sticky="w", padx=grid_padx, pady=(0, 4))
            self.ecc_var = tk.StringVar(value=DEFAULT_ECC)
            self.ecc_menu = ctk.CTkOptionMenu(parent, variable=self.ecc_var, values=["L", "M", "Q", "H"], command=lambda _v: self._maybe_autoupdate())
            self.ecc_menu.grid(row=10, column=0, sticky="ew", padx=grid_padx, pady=(0, grid_pady))

            help_btn = ctk.CTkButton(parent, text="What is this?", command=lambda: messagebox.showinfo(APP_TITLE, ECC_HELP_TEXT))
            help_btn.grid(row=11, column=0, sticky="w", padx=grid_padx, pady=(0, 6))
        else:
            tk.Label(parent, text="QR Error Correction").grid(row=9, column=0, sticky="w", padx=grid_padx, pady=(0, 3))
            self.ecc_var = tk.StringVar(value=DEFAULT_ECC)
            self.ecc_menu = tk.OptionMenu(parent, self.ecc_var, "L", "M", "Q", "H", command=lambda _v: self._maybe_autoupdate())
            self.ecc_menu.grid(row=10, column=0, sticky="ew", padx=grid_padx, pady=(0, grid_pady))

            tk.Button(parent, text="What is this?", command=lambda: messagebox.showinfo(APP_TITLE, ECC_HELP_TEXT)).grid(
                row=11, column=0, sticky="w", padx=grid_padx, pady=(0, 6)
            )

        if USE_CTK:
            ctk.CTkLabel(parent, text="Quiet zone / border (modules)").grid(row=12, column=0, sticky="w", padx=grid_padx, pady=(0, 4))
            self.border_var = tk.StringVar(value=str(DEFAULT_BORDER))
            self.border_entry = ctk.CTkEntry(parent, textvariable=self.border_var)
            self.border_entry.grid(row=13, column=0, sticky="ew", padx=grid_padx, pady=(0, grid_pady))
        else:
            tk.Label(parent, text="Quiet zone / border (modules)").grid(row=12, column=0, sticky="w", padx=grid_padx, pady=(0, 3))
            self.border_var = tk.StringVar(value=str(DEFAULT_BORDER))
            self.border_entry = tk.Entry(parent, textvariable=self.border_var)
            self.border_entry.grid(row=13, column=0, sticky="ew", padx=grid_padx, pady=(0, grid_pady))

        self.autoupdate_var = tk.BooleanVar(value=False)
        if USE_CTK:
            self.autoupdate_cb = ctk.CTkCheckBox(parent, text="Auto-update preview as I type", variable=self.autoupdate_var, command=self._maybe_autoupdate)
            self.autoupdate_cb.grid(row=14, column=0, sticky="w", padx=grid_padx, pady=(4, 12))
        else:
            self.autoupdate_cb = tk.Checkbutton(parent, text="Auto-update preview as I type", variable=self.autoupdate_var, command=self._maybe_autoupdate)
            self.autoupdate_cb.grid(row=14, column=0, sticky="w", padx=grid_padx, pady=(4, 10))

        for w in [self.dpi_entry, self.inches_entry, self.px_entry, self.border_entry]:
            self._bind_live_update(w)

    # -----------------------------
    # Profiles
    # -----------------------------
    def _load_profiles(self) -> List[Profile]:
        data = safe_read_json(self.profiles_path)
        out: List[Profile] = []
        for item in data.get("profiles", []):
            try:
                out.append(Profile(**item))
            except Exception:
                continue
        return out[:PROFILES_MAX]

    def _persist_profiles(self) -> None:
        data = {"profiles": [asdict(p) for p in self.profiles[:PROFILES_MAX]]}
        safe_write_json(self.profiles_path, data)

    def _profile_display_list(self) -> List[str]:
        if not self.profiles:
            return ["Recent Profiles (Load)"]
        return ["Recent Profiles (Load)"] + [p.name for p in self.profiles]

    def _refresh_profiles_dropdown(self) -> None:
        values = self._profile_display_list()
        if USE_CTK:
            self.profile_menu.configure(values=values)
        else:
            menu = self.profile_menu["menu"]
            menu.delete(0, "end")
            for v in values:
                menu.add_command(label=v, command=lambda val=v: self._set_and_select_profile(val))

    def _set_and_select_profile(self, value: str) -> None:
        self.profile_var.set(value)
        self.on_profile_select(value)

    def _save_current_profile_to_recent(self) -> None:
        ssid = self.ssid_var.get()
        auth = self.auth_var.get()
        name = f"{ssid if ssid else '(empty SSID)'} — {auth}"

        target_px, dpi, inches, _mode = self._compute_target_px_and_dpi()
        px_size = target_px

        p = Profile(
            name=name,
            ssid=ssid,
            auth=auth,
            hidden=bool(self.hidden_var.get()),
            dpi=dpi,
            ecc=getattr(self, "ecc_var", tk.StringVar(value=DEFAULT_ECC)).get(),
            border=self._parse_int(getattr(self, "border_var", tk.StringVar(value=str(DEFAULT_BORDER))).get(), DEFAULT_BORDER, 0, 20),
            size_mode=getattr(self, "size_mode_var", tk.StringVar(value="inches")).get(),
            inches=inches,
            px_size=px_size,
            dark_mode=self.appearance_var.get() if self.appearance_var.get() in ("Dark", "Light") else "Dark",
        )

        def key(x: Profile) -> Tuple:
            return (x.ssid, x.auth, x.hidden, x.dpi, x.ecc, x.border, x.size_mode, x.inches, x.px_size, x.dark_mode)

        self.profiles = [x for x in self.profiles if key(x) != key(p)]
        self.profiles.insert(0, p)
        self.profiles = self.profiles[:PROFILES_MAX]
        self._persist_profiles()
        self._refresh_profiles_dropdown()

    def on_save_profile(self) -> None:
        self._save_current_profile_to_recent()
        messagebox.showinfo(APP_TITLE, "Saved current settings to Recent Profiles.")

    def on_profile_select(self, selected: Optional[str] = None) -> None:
        name = selected if selected is not None else self.profile_var.get()
        if not name or name == "Recent Profiles (Load)":
            return
        match = next((p for p in self.profiles if p.name == name), None)
        if not match:
            return

        self.ssid_var.set(match.ssid)
        self.auth_var.set(match.auth if match.auth in AUTH_OPTIONS else AUTH_OPTIONS[2])
        self.hidden_var.set(bool(match.hidden))

        if hasattr(self, "dpi_var"):
            self.dpi_var.set(str(match.dpi))
            self.ecc_var.set(match.ecc if match.ecc in ("L", "M", "Q", "H") else DEFAULT_ECC)
            self.border_var.set(str(match.border))
            self.size_mode_var.set(match.size_mode if match.size_mode in ("inches", "pixels") else "inches")
            self.inches_var.set(str(match.inches))
            self.px_var.set(str(match.px_size))

            if int(match.dpi) == 300 and abs(float(match.inches) - DEFAULT_INCHES) < 1e-6 and match.size_mode == "inches":
                self.preset_var.set("2x2 in @ 300 DPI (Default)")
            elif int(match.dpi) == 600 and abs(float(match.inches) - DEFAULT_INCHES) < 1e-6 and match.size_mode == "inches":
                self.preset_var.set("2x2 in @ 600 DPI")
            else:
                self.preset_var.set("Custom (Advanced)")

        if USE_CTK and match.dark_mode in ("Dark", "Light"):
            self.appearance_var.set(match.dark_mode)
            ctk.set_appearance_mode(match.dark_mode)

        self._update_warning_label()

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    try:
        app = WiFiQRApp()
        app.run()
    except Exception:
        exc_type, exc_value, exc_tb = sys.exc_info()
        if exc_type is not None:
            global_excepthook(exc_type, exc_value, exc_tb)


if __name__ == "__main__":
    main()
