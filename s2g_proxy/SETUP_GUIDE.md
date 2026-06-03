# S2G Proxy (Session-to-Gate) Setup & Execution Guide

This guide provides step-by-step instructions to set up and run the S2G client-side zero-trust session hijacking protection demonstration on a Windows machine.

---

## 🛠️ Step 1: Environment & Dependency Setup

1. **Open PowerShell** as a normal user and navigate to the project directory:
   ```powershell
   cd D:\projects\s2g\s2g_proxy
   ```

2. **Recreate the Virtual Environment** using Python 3.12 (required for PyQt6 compatibility):
   * *If Python 3.12 is not installed, install it via winget:*
     ```powershell
     winget install -e --id Python.Python.3.12 --source winget --accept-package-agreements --accept-source-agreements
     ```
   * *Recreate the venv:*
     ```powershell
     Remove-Item -Recurse -Force venv -ErrorAction SilentlyContinue
     & "$env:LocalAppData\Programs\Python\Python312\python.exe" -m venv venv
     ```

3. **Upgrade Pip & Install Dependencies**:
   ```powershell
   venv\Scripts\python.exe -m pip install --upgrade pip
   venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

---

## 🔑 Step 2: Install the Proxy HTTPS Root Certificate

Because S2G intercepts and secures cookies over HTTPS, your system must trust its local signing certificate:

1. **Trust the Certificate (Recommended)**:
   Run the following PowerShell command to import the `mitmproxy` certificate into your user account's Trusted Root store:
   ```powershell
   Import-Certificate -FilePath "certs\mitmproxy-ca-cert.cer" -CertStoreLocation Cert:\CurrentUser\Root
   ```
2. **Restart your browser** (fully close all open Chrome processes) to apply the change.

---

## 🚀 Step 3: Running the Security Demo

Follow these steps in order to demonstrate S2G's session hijacking prevention:

### 1. Launch the S2G Proxy Dashboard
Run the dashboard GUI:
```powershell
venv\Scripts\python.exe app.py
```
* **Action:** Click **🚀 Start Enforcer**. The status will change to **Active & Protected** (listening on port 8080).

### 2. Launch the Demo Browser
In a separate terminal, launch the isolated Chrome window routed through S2G:
```powershell
.\start_browser_demo.bat
```
* **Action:** Go to the launched Google Gruyere page, click **Sign Up** (top right) to create a test account, and log in.
* **Observe:** Press `F12` to open DevTools, navigate to **Application -> Storage -> Cookies**. The `GRUYERE_ID` cookie value will be encrypted and prefixed with `S2G_VAULT_...`.

### 3. Simulate Cookie Theft (Malware PoC)
Open a **new PowerShell window as Administrator** (right-click -> *Run as administrator*) and run:
```powershell
cd D:\projects\s2g\s2g_proxy
venv\Scripts\python.exe cookie_stealer_poc.py
```
* **Observe:** The malware successfully bypasses Windows DPAPI and steals Chrome's cookie database, but the stolen `GRUYERE_ID` is just the `S2G_VAULT_...` ciphertext. The attacker cannot decrypt it on another computer because it is bound to your machine's hardware UUID.

### 4. Simulate Network Hijacking (Attacker Block)
In a normal PowerShell window, run the attacker script:
```powershell
venv\Scripts\python.exe demo_attacker.py
```
* **Observe:** The script attempts to send requests to Google Gruyere using a stolen cookie. The connection is immediately terminated, and you will see process block logs (like `Blocked unauthorized process: python.exe`) in the **S2G Proxy Dashboard**!
