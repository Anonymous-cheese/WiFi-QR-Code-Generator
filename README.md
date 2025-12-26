# WiFi QR Code Generator

A lightweight desktop utility for generating Wi-Fi connection QR codes compatible with modern iOS and Android devices.

Built with Python and CustomTkinter, this tool allows you to quickly create, preview, export, and share Wi-Fi QR codes without installers or complex setup.

---

## Features

- Generates iOS & Android compatible Wi-Fi QR codes
- Supports common non-enterprise Wi-Fi security types:
  - Open / None
  - WEP (legacy, with warning)
  - WPA / WPA2-Personal (PSK)
  - WPA3-Personal (SAE, encoded for compatibility)
  - WPA2 / WPA3-Personal (mixed)
- Live QR preview inside the app
- Export QR codes as PNG (print-ready) and SVG (vector)
- Copy QR image or raw payload text to clipboard
- Dark / Light mode toggle
- Advanced options (hidden by default):
  - DPI control
  - Error correction level
  - Quiet zone / border size
  - Pixel-based sizing
- Saves up to 5 recent profiles locally
- Portable single-file EXE (no installer)

---

## QR Code Compatibility

The application uses the standard Wi-Fi QR payload format understood by modern phones:

WIFI:T:WPA;S:MyNetwork;P:MyPassword;H:false;;

Notes:
- Enterprise / 802.1X networks are not supported
- WPA3 and mixed modes are encoded using the closest compatible format accepted by phone scanners

---

## QR Error Correction (What It Does)

QR codes include built-in redundancy so they can still scan if partially damaged, blurry, or obscured.

Level L (~7%)  
Smallest QR, least tolerant to damage

Level M (~15%)  
Recommended default, best balance

Level Q (~25%)  
More durable, denser QR

Level H (~30%)  
Most durable, densest QR

Higher levels increase durability but make the QR more complex and dense.

---

## Usage

1. Enter the SSID
2. Select Encryption / Authentication
3. Enter the password (if required)
4. Click Generate / Update QR
5. Export or copy the QR code as needed

Advanced options are available under Show Advanced Options.

---

## Profiles

- Automatically saves up to 5 recent profiles
- Profiles include SSID, authentication type, hidden flag, and advanced settings
- Profiles are stored locally in a JSON file in the user directory
- Includes a Clear Recent Profiles button

---

## Distribution Notes (Important)

- The application is distributed as an unsigned portable EXE
- Windows SmartScreen may display a warning
- This is expected for unsigned public software
- The app does not install anything and makes no system-level changes

---

## Building From Source

Requirements:
- Python 3.9+
- pip

Install dependencies:

pip install customtkinter qrcode[pil] pillow

Run from source:

python wifi_qr_code_generator.py

---

## Building the Portable EXE (Windows)

pip install pyinstaller

pyinstaller --clean --onefile --windowed --name "WiFi QR Code Generator" wifi_qr_code_generator.py

Output:

dist\WiFi QR Code Generator.exe

- Single executable
- No installer
- No console window

---

## Limitations

- No enterprise (802.1X) Wi-Fi support
- Unsigned EXE (SmartScreen warnings possible)
- Clipboard image copy support may vary by OS

---

## Public Repository Notes

This project is intended for public distribution.  
Users should expect standard Windows security prompts when running unsigned executables.
