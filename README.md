# PrintDash

<img width="1376" height="768" alt="PrintDash Banner" src="https://github.com/user-attachments/assets/312fb595-4a8f-41dc-8233-bd5df12c4ded" />

A self-hosted office printer management dashboard with SNMP-based toner/status monitoring, print job control, network scanning, and Telegram alerts — all from a single Node.js process.

---

## Features

### Printer Monitoring
- SNMP polling of networked printers (Canon, HP, and others)
- Toner/ink levels per cartridge with low-toner threshold alerts
- Paper tray status and empty tray detection
- Jam, cover-open, and service alert detection
- Online/offline state with consecutive-failure debounce (avoids false alarms from transient SNMP timeouts)
- Page count tracking with history per printer
- Uptime display

### Print Management (via CUPS)
- View all CUPS print queues and their current status
- Submit print jobs directly from the dashboard (file upload)
- Live and completed job history with job cancellation
- Pause/resume individual print queues
- Set default printer
- Discover IPP printers on the local network and add them to CUPS in one click

### Scanning (via SANE + Samba)
- Detect connected scanners via `scanimage`
- Trigger scans remotely from the dashboard
- Browse and download completed scan files
- Built-in Samba config helper — generates the `/etc/samba/smb.conf` snippet so Canon/HP printers can scan-to-folder directly to the server over SMB (`\\SERVER_IP\scans`)

### Printer Discovery
- SNMP subnet scan to auto-discover printers on your network
- Automatic local subnet detection
- IPP/CUPS discovery as an alternative to SNMP
- One-click add from scan results

### Alerts (Telegram)
- Instant notifications for low toner, paper empty, jams, offline, and back-online events
- Per-alert type toggles (enable/disable individually)
- Configurable toner threshold percentage
- Alert cooldown to prevent repeated notifications for the same condition
- Alert state persisted to disk — server restarts do not re-fire already-sent alerts
- Test message button to verify your bot token and chat ID

### Dashboard & Auth
- Dark-themed responsive web UI
- Role-based login — `admin` (full access) and `user` (read-only monitoring)
- Admin user management (add, change password, delete)
- Settings page with live Telegram configuration

 <img width="1897" height="904" alt="2026-07-06 16_58_24-PrintDash and 25 more pages - Personal - Microsoft​ Edge" src="https://github.com/user-attachments/assets/fc40b844-6459-400f-8ea5-0022417cb3ec" />

---

## Requirements

- Node.js 18+
- Network access (SNMP, UDP 161) to your printers
- **CUPS**  for print queue management, job control, and IPP-based printer discovery
- **SANE** (`scanimage`) for scanner support
- **Samba** (`smbd`) if you want scan-to-folder from printer web UIs

***On Debian/Ubuntu:***

## 1. Installation

```bash
sudo apt update
sudo apt install -y cups cups-client sane-utils sane-airscan samba printer-driver-all
sudo usermod -aG lpadmin $USER

# Grant non-root write permission for SANE scanner auto-provisioning:
sudo chown root:lpadmin /etc/sane.d/airscan.conf 2>/dev/null || true
sudo chmod 664 /etc/sane.d/airscan.conf 2>/dev/null || true

git clone https://github.com/ramadhan24021996/PrintServer.git
cd PrintServer
npm install
cp printers.example.json printers.json
cp settings.example.json settings.json
```

## 2. Run

```bash
npm start
```

Production (PM2):

```bash
pm2 start server.js --name printdash
pm2 save

```

## 3. Dashboard

Open `http://SERVER_IP:3003`

**Default login**
```
Username: admin
Password: admin123
```

## 4. Add a printer

1.  Overview → **+ Add Printer**
2.  Enter Name, IP address, Brand, SNMP community (`public`)
3.  Check **"Also create CUPS print queue + SANE scan device"**
4.  Save

This creates:

-   SNMP monitoring entry
-   CUPS print queue: `lpadmin -p "<name>" -E -v ipp://<ip>/ipp/print -m everywhere`
-   SANE scan entry in `/etc/sane.d/airscan.conf`: `"<name>" = http://<ip>:80/eSCL, eSCL`

## 5. If auto-provisioning fails, add manually

CUPS:

```bash
lpadmin -p "PrinterName" -E -v ipp://192.168.x.x/ipp/print -m everywhere
lpstat -p
```

SANE — edit `/etc/sane.d/airscan.conf`, under `[devices]`:
```
"PrinterName" = http://192.168.x.x:80/eSCL, eSCL

scanimage -L
```

Name must match exactly in: PrintDash printer name, CUPS queue name, airscan.conf entry.

## 6. Add a user

1.  Users → Add User
2.  Enter username, password
3. Select a Role

## 7. Enable scan-to-folder from the printer

1.  Settings → Scans → copy the Samba config block
2.  Add to `/etc/samba/smb.conf`
```bash
systemctl restart smbd
```
3.  On printer web UI: Scan → Scan to Folder → `\\SERVER_IP\scans`



## Default Environment variables

-   `USERS_FILE` — default `./users.json`
-   `SESSIONS_FILE` — default `./sessions.json`
-   `DATA_FILE` — default `./printers.json`
-   `SETTINGS_FILE` — default `./settings.json`
-   `SCAN_DIR` — default `/opt/scans`
-   `UPLOAD_DIR` — default `/tmp/printdash-uploads`
-   `AIRSCAN_CONF` — default `/etc/sane.d/airscan.conf`

## License

MIT
