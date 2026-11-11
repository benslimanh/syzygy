#!/bin/bash
############################################################################
#                                                                          #
#   ____ ___  _ ____ ___  _ ________  _                                    #
#  / ___\\  \///_   \\  \///  __/\  \//                                    #
#  |    \ \  /  /   / \  / | |  _ \  /                                     #
#  \___ | / /  /   /_ / /  | |_// / /                                      #
#  \____//_/   \____//_/   \____\/_/                                       #
#                                                                          #
#  Syzygy                                                                  #
#                                                                          #
#  Created by Hamza Bensliman <benslimanh> for 2026                        #
#                                                                          #
#  This software is licensed under the terms of the MIT license.           #
#  You may use, copy, modify, merge, publish, distribute and/or sell       #
#  copies of the Software, and permit persons to whom the Software is      #
#  furnished to do so, under the terms of the MIT license.                 #
#                                                                          #
#  This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF   #
#  ANY KIND, either express or implied.                                    #
#                                                                          #
############################################################################

set -e

echo "[*] Building production binary..."
make clean >/dev/null
make >/dev/null

echo "[*] Setting up directories..."
sudo mkdir -p /etc/syzygy/ssl
sudo mkdir -p /var/www/syzygy
sudo chown nobody:nogroup /var/www/syzygy || sudo chown nobody:nobody /var/www/syzygy
sudo mkdir -p /var/log/syzygy
sudo chown nobody:nogroup /var/log/syzygy || sudo chown nobody:nobody /var/log/syzygy

echo "[*] Installing binary..."
sudo cp syzygy /usr/local/bin/

echo "[*] Installing SSL certificates..."
sudo cp ssl/server.crt /etc/syzygy/ssl/
sudo cp ssl/server.key /etc/syzygy/ssl/
sudo chmod 600 /etc/syzygy/ssl/server.key

echo "[*] Creating default index.html..."
echo "<h1>Welcome to Syzygy (Pilot Deployment)</h1><p>Server is running successfully via systemd!</p>" | sudo tee /var/www/syzygy/index.html >/dev/null

echo "[*] Installing systemd service..."
sudo cp systemd/syzygy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable syzygy
sudo systemctl restart syzygy

echo "[*] Verifying deployment..."
sleep 2
sudo systemctl --no-pager status syzygy
echo "[*] Testing HTTP (Port 80)..."
curl -s http://127.0.0.1/
echo -e "\n[*] Testing HTTPS (Port 443)..."
curl -sk https://127.0.0.1/
echo -e "\n[*] Pilot Deployment Complete!"
