# PrintServer

<img width="1376" height="768" alt="PrintServer Banner" src="./banner.png" />

A powerful, self-hosted office printer & scanner management dashboard with SNMP-based toner/status monitoring, CUPS print queue control, remote SANE scanning, mobile camera scan, private document sharing, Telegram alerts, print history PDF exports, and Mobile PWA support — all running from a single Node.js process.

---

## 🌟 Key Features

### 🖨️ Printer Monitoring & Persistent Storage
- **SNMP Polling**: Real-time polling for networked printers (Canon, HP, Epson, Brother, Ricoh, Xerox, etc.).
- **Toner & Supply Tracking**: Detailed percentage levels per cartridge with customizable low-toner alerts.
- **Paper & Hardware Status**: Paper tray level detection, paper empty alerts, jam detection, cover open, and service warnings.
- **Reliable Debounce**: Online/offline detection with consecutive-failure debounce to eliminate false alarms from temporary SNMP timeouts.
- **Page Counter & Uptime**: Print volume history tracking per printer and server uptime stats.
- **Auto-Synced CUPS Persistence**: Registered CUPS printers are automatically synchronized and permanently stored in `data/printers.json`. They remain assigned across server and container restarts, marked with `✓ Terdaftar & Tersimpan` in Network Discovery.

### 📋 Print Management (CUPS Integration)
- **Queue Control**: View all active CUPS print queues, pause/resume queues, and set default printer.
- **Dashboard File Printing**: Direct file printing from web UI (supports PDF, DOCX, XLSX, TXT, JPG, PNG).
- **Job Control & Cancellation**: Cancel active/pending print jobs directly from the dashboard.
- **Print History & PDF Export**: View complete history, filter/group by user or printer, multi-select deletion, and 1-click **Export to PDF** with automated 30-day report reminder.
- **Interactive Action Modals**: Modern success popup modals with animated checkmark & confetti, and detailed error modals for all print operations on both Mobile and Desktop UI.

### 📄 Scanner & Camera Scan (SANE + eSCL + HP Camera)
- **Remote Web Scanning**: Trigger hardware scans from connected SANE/eSCL scanners directly from the web browser.
- **📷 Camera Scan via Mobile HP**: Use smartphone cameras to scan paper documents on the go. Converts photos automatically into PDF or PNG format, saved directly to the server scan storage.
- **Scan-to-Print & Share**: 1-click Print to any server printer, Preview, Download, or Share via WhatsApp, Telegram, and Google Drive (via Web Share API).
- **Scan-to-Folder (SMB)**: Built-in Samba config generator for `/etc/samba/smb.conf` so Canon/HP network printers can scan directly to `\\SERVER_IP\scans`.

### 📂 Private Shared Documents & Privacy Control
- **Targeted Sharing**: Upload documents to the shared library and target specific users (`Semua User` or individual target users).
- **Strict Privacy Access**: Private documents are strictly visible, downloadable, and printable ONLY by the target recipient and admin.
- **📩 Unread Badge Notification**: Mobile UI features a live `📩 X Baru` badge highlighting unread private documents for the logged-in user.
- **📊 Audit History Log**: Dedicated access history table tracking every download, print, and view event per document.

### 🔍 Auto Printer Discovery
- **Subnet SNMP Scanner**: Scan local IP subnets to auto-detect network printers.
- **CUPS Network Discovery (`lpinfo`)**: Detect IPP, mDNS, LPD, Socket, and USB printers. Discovered printers already registered are clearly badged (`✓ Terdaftar & Tersimpan`).
- **1-Click Auto-Provisioning**: Automatically creates CUPS print queue (`ipp://<ip>/ipp/print`) and SANE scanner entry (`airscan.conf`) in one click.

### 📱 Mobile PWA & QR Code Access
- **Installable PWA**: Mobile-optimized web application (`/mobile`) with web app manifest and service worker.
- **QR Token Access**: Admin generates per-user QR codes/tokens for instant passwordless mobile login.
- **Mobile Action Hub**: Print files, capture camera scans, view private shared documents, and send print jobs directly from smartphones.

### 👥 Multi-Printer User Management & Groups
- **Role-Based Auth**: `admin` (full management access) and `user` (restricted printer access).
- **Multi-Printer Assignment**: Assign specific printer access privileges per user. Instant detection and auto-refresh on existing user lists upon creation with interactive feedback modals.
- **User Groups**: Organize users and printers into customizable groups for structured access control.

### 🔔 Telegram Alerts
- **Real-Time Notifications**: Instant alert messages for low toner, empty paper, paper jams, offline state, and back-online recovery.
- **Fine-Grained Toggles**: Enable or disable specific alert types individually.
- **Alert Cooldown & Persistence**: Cooldown timer prevents duplicate spam; state is saved to disk so server restarts don't re-trigger existing alerts.
- **Test Message Button**: Send a test alert to verify bot token and Chat ID.

### 💾 1-Click Backup & Restore
- **Export Backup**: Download a single `.json` backup file containing all system configurations (Printers, Users, Settings, Groups, Mobile Tokens, Job Metadata).
- **Import Restore**: Restore all configurations to PrintServer in 1-click with safety confirmation and automatic persistence to disk.

---

<img width="1897" height="904" alt="PrintServer Dashboard Overview" src="./dashboard.png" />

---

## 🛠️ System Requirements

- **OS**: Linux (Debian / Ubuntu / Raspberry Pi OS recommended)
- **Node.js**: 18.0 or higher
- **Network**: SNMP access (UDP port 161) to network printers
- **Dependencies**: CUPS (`cupsd`), SANE (`sane-utils`, `sane-airscan`), Samba (`smbd` optional for Scan-to-Folder), LibreOffice (optional for DOCX/XLSX printing)

---

## 🚀 Installation Guide

### Option 1: Direct Host Installation (Recommended for CUPS/SANE)

#### 1. Install System Dependencies (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install -y cups cups-client sane-utils sane-airscan samba printer-driver-all libreoffice-writer-nogui libreoffice-calc-nogui
sudo usermod -aG lpadmin $USER

# Grant permissions for SANE scanner auto-provisioning
sudo touch /etc/sane.d/airscan.conf
sudo chown root:lpadmin /etc/sane.d/airscan.conf 2>/dev/null || true
sudo chmod 664 /etc/sane.d/airscan.conf 2>/dev/null || true
```

#### 2. Clone Repository & Install Node Modules

```bash
git clone https://github.com/ramadhan24021996/PrintServer.git
cd PrintServer
npm install
cp printers.example.json printers.json
cp settings.example.json settings.json
```

#### 3. Start Server

```bash
# Development / Testing
npm start

# Production with PM2
sudo npm install -g pm2
pm2 start server.js --name printserver
pm2 save
```

Open the dashboard, then follow the usage guide below.

---

### Option 2: Docker / Docker Compose

```bash
docker compose up -d --build
```

---

### Option 3: Portainer Stack Deployment

1. Open **Portainer** (`http://SERVER_IP:9000`) → Select your environment (**local**).
2. Go to **Stacks** → Click **+ Add stack**.
3. Name the stack: `printserver`.
4. Select **Repository** build method:
   - **Repository URL**: `https://github.com/ramadhan24021996/PrintServer.git`
   - **Repository reference**: `refs/heads/main`
   - **Compose path**: `docker-compose.yml`
5. Click **Deploy the stack**.

---

## 🌐 Dashboard Access

Open your browser and navigate to: `http://SERVER_IP:3003`

**Default Credentials:**
- **Username:** `admin`
- **Password:** `admin123`

*(Make sure to change the admin password upon initial login in the Users section).*

---

## 📖 Usage Guide

### 1. Add a printer
1. Overview → **+ Add Printer**
2. Enter Name, IP address, Brand, SNMP community (`public`)
3. Check **"Also create CUPS print queue + SANE scan device"**
4. Save

This creates:
- SNMP monitoring entry
- CUPS print queue: `lpadmin -p "<name>" -E -v ipp://<ip>/ipp/print -m everywhere`
- SANE scan entry in `/etc/sane.d/airscan.conf`: `"<name>" = http://<ip>:80/eSCL, eSCL`

### 2. Camera Scan via Smartphone (Mobile PWA)
1. Scan QR code or navigate to `/mobile` on mobile browser.
2. Go to **Scan Dokumen** tab -> Tap **📷 Ambil Foto / Scan via Kamera HP**.
3. Take a photo of the document.
4. Document will be converted to PDF/PNG and shown in scan results with options:
   - 🖨 **Print**: Send directly to chosen server printer.
   - 👁 **Preview**: View scanned photo.
   - 📤 **Share**: Share to WhatsApp, Telegram, or Drive.
   - ⬇ **Download**: Download file locally.

### 3. Send Private Shared Document to Specific User
1. Open **Shared Documents** menu in Dashboard or Mobile UI.
2. Select target user from dropdown (e.g. `user1` or `Semua User`).
3. Upload file (PDF, DOCX, TXT, PNG, JPG).
4. The target user receives a `📩 1 Baru` badge notification on their mobile UI and can view/download/print the document.

### 4. Enable scan-to-folder from the printer
1. Settings → Scans → copy the Samba config block
2. Add it to `/etc/samba/smb.conf`, then:
```bash
sudo systemctl restart smbd
```
3. On the printer web UI: Scan → Scan to Folder → `\\SERVER_IP\scans`

---

## 🖥️ Client PC Setup (Printing via PrintServer)

PrintServer creates the printer queues in **CUPS** on the server. For client PCs to print through the server, CUPS printer sharing must be enabled.

### Server side (one time)

```bash
# Share printers over the network (IPP, port 631)
sudo cupsctl --share-printers --remote-any
sudo lpadmin -p "PrinterName" -o printer-is-shared=true   # repeat per printer
sudo systemctl restart cups

# Allow port 631 if a firewall is active
sudo ufw allow 631/tcp
```

> By default CUPS listens on `localhost` only (`_share_printers=0`), so clients cannot reach it until sharing is enabled. Check with `cupsctl`.

Printer URL used by clients (queue name = the printer name in PrintServer):

```
http://SERVER_IP:631/printers/PrinterName
```

### Windows 10/11
1. Settings → Bluetooth & devices → Printers & scanners → **Add device** → *Add manually*
2. Choose **Select a shared printer by name** and enter `http://SERVER_IP:631/printers/PrinterName`
3. Pick a driver (or *Microsoft IPP Class Driver* / *Generic* if prompted), then finish.

### Linux
```bash
lpadmin -p "PrinterName" -E -v ipp://SERVER_IP:631/printers/PrinterName -m everywhere
lpstat -p
```
Or use Settings → Printers → Add → enter the IPP URL.

### macOS
System Settings → Printers & Scanners → **+** → *IP* tab → Protocol **Internet Printing Protocol - IPP**, Address `SERVER_IP:631`, Queue `printers/PrinterName`.

---

## ⚙️ Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `3003` | HTTP web server port |
| `DATA_FILE` | `./printers.json` | Path to printer list JSON |
| `USERS_FILE` | `./users.json` | Path to user accounts JSON |
| `SETTINGS_FILE` | `./settings.json` | Path to system settings & Telegram config |
| `SESSIONS_FILE` | `./sessions.json` | Path to active user sessions |
| `ALERT_STATE_FILE` | `./alert-state.json` | Path to persisted alert cooldown state |
| `SCAN_DIR` | `/opt/scans` | Storage path for scanned files |
| `UPLOAD_DIR` | `/tmp/printserver-uploads` | Storage path for uploaded print jobs |
| `AIRSCAN_CONF` | `/etc/sane.d/airscan.conf` | Location of SANE airscan configuration file |
| `JOB_METADATA_FILE` | `./job-metadata.json` | Print job metadata (user, document name) |
| `GROUPS_FILE` | `./groups.json` | Path to groups JSON |
| `DELETED_JOBS_FILE` | `./data/deleted-jobs.json` | Records of deleted history entries |
| `MOBILE_TOKENS_FILE` | `./mobile-tokens.json` | Mobile QR access tokens |
| `SHARED_DOCS_DIR` | `/opt/shared-docs` | Storage path for shared documents |

---

## 📄 License

Distributed under the [MIT License](LICENSE).
