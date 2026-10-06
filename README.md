# PrintServer

<img width="1376" height="768" alt="PrintServer Banner" src="https://github.com/user-attachments/assets/312fb595-4a8f-41dc-8233-bd5df12c4ded" />

A powerful, self-hosted office printer & scanner management dashboard with SNMP-based toner/status monitoring, CUPS print queue control, remote SANE scanning, Telegram alerts, print history PDF exports, and Mobile PWA support — all running from a single Node.js process.

---

## Features

### 🖨️ Printer Monitoring
- **SNMP Polling**: Real-time polling for networked printers (Canon, HP, Epson, Brother, Ricoh, Xerox, etc.).
- **Toner & Supply Tracking**: Detailed percentage levels per cartridge with customizable low-toner alerts.
- **Paper & Hardware Status**: Paper tray level detection, paper empty alerts, jam detection, cover open, and service warnings.
- **Reliable Debounce**: Online/offline detection with consecutive-failure debounce to eliminate false alarms from temporary SNMP timeouts.
- **Page Counter & Uptime**: Print volume history tracking per printer and server uptime stats.

### 📋 Print Management (CUPS Integration)
- **Queue Control**: View all active CUPS print queues, pause/resume queues, and set the default printer.
- **Dashboard File Printing**: Direct file printing from web UI (supports PDF, DOCX, XLSX, TXT, and image files).
- **Job Control & Cancellation**: Cancel active/pending print jobs directly from the dashboard.
- **Print History & PDF Export**: View complete history, filter/group by user or printer, multi-select deletion, and 1-click **Export to PDF** with automated 30-day report reminder.

### 📄 Scanner & Samba Support (SANE + SMB)
- **Remote Web Scanning**: Trigger scans from connected SANE scanners directly from the browser UI.
- **Scan File Management**: View, preview, and download scanned documents.
- **Scan-to-Folder (SMB)**: Built-in Samba config generator for `/etc/samba/smb.conf` so Canon/HP network printers can scan directly to `\\SERVER_IP\scans`.

### 🔍 Auto Printer Discovery
- **Subnet SNMP Scanner**: Scan local IP subnets to auto-detect network printers.
- **1-Click Auto-Provisioning**: Automatically creates CUPS print queue (`ipp://<ip>/ipp/print`) and SANE scanner entry (`airscan.conf`) in one click.
- **IPP / CUPS Discovery**: Alternative IPP mDNS discovery for local subnet printers.

### 📱 Mobile PWA & QR Code Access
- **Installable PWA**: Mobile-first progressive web app with offline status indicator.
- **Instant QR Pairing**: Administrator can generate user QR codes for quick passwordless mobile login.

### 🔔 Telegram Alerts
- **Real-Time Notifications**: Instant alert messages for low toner, empty paper, paper jams, offline state, and back-online recovery.
- **Fine-Grained Toggles**: Enable or disable specific alert types individually.
- **Alert Cooldown & Persistence**: Cooldown timer prevents duplicate spam; state is saved to disk so server restarts don't re-trigger existing alerts.
- **Test Message Button**: Send a test alert to verify bot token and Chat ID.

### 🔐 Security & Access Control
- **Role-Based Auth**: `admin` (full management access) and `user` (read-only monitoring & printing).
- **User Management**: Add new users, manage roles, change passwords, and track user sessions.

---

<img width="1897" height="904" alt="PrintServer Dashboard Overview" src="https://github.com/user-attachments/assets/fc40b844-6459-400f-8ea5-0022417cb3ec" />

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

---

### Option 2: Docker / Docker Compose

```bash
docker-compose up -d
```

---

## 🌐 Dashboard Access

Open your browser and navigate to: `http://SERVER_IP:3003`

**Default Credentials:**
- **Username:** `admin`
- **Password:** `admin123`

*(Make sure to change the admin password upon initial login in the Users section).*

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

---

## 📄 License

Distributed under the [MIT License](LICENSE).
