FROM node:18-bookworm-slim

# Install system dependencies: CUPS, SANE, airscan, ping, etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    cups \
    cups-client \
    sane-utils \
    sane-airscan \
    printer-driver-all \
    iputils-ping \
    ca-certificates \
    libreoffice-writer-nogui \
    libreoffice-calc-nogui \
    && usermod -aG lpadmin node \
    && mkdir -p /etc/sane.d \
    && touch /etc/sane.d/airscan.conf \
    && chown root:lpadmin /etc/sane.d/airscan.conf \
    && chmod 664 /etc/sane.d/airscan.conf \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package definition and install production dependencies
COPY package*.json ./
RUN npm install --production

# Copy application files
COPY . .

# Entrypoint script to start background services (like CUPS)
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create scan and upload directories
RUN mkdir -p /opt/scans /tmp/printserver-uploads /app/data && chown -R node:node /app /opt/scans /tmp/printserver-uploads

EXPOSE 3003

ENTRYPOINT ["/entrypoint.sh"]
CMD ["node", "server.js"]
