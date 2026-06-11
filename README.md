# h0zelpanel

Panneau de contrôle web léger pour gérer des process **PM2** à distance.
Interface iOS-style, authentification par mot de passe, logs en direct.


## Fonctionnalités
- Vue temps réel des process PM2 (CPU, RAM, uptime, redémarrages)
- Boutons Start / Stop / Restart
- Logs stdout/stderr en direct avec coloration ANSI
- Vue logs plein écran
- Métriques système (RAM, load, uptime)
- Auth par mot de passe + anti brute-force
- Design responsive (mobile + desktop)


## Installation

```bash
# 1. Installer les dépendances
npm install

# 2. Configurer
cp .env.example .env
nano .env          # définir PANEL_PASSWORD (12 car. min)

# 3. Lancer
node server.js
# ou avec PM2 :
pm2 start server.js --name panel
pm2 save
```

Accès : `http://IP_DU_SERVEUR:7777`


## Configuration (.env)

| Variable | Défaut | Description |
|----------|--------|-------------|
| `PANEL_PASSWORD` | — | **Obligatoire**, 12 caractères min |
| `PANEL_PORT` | 7777 | Port d'écoute |
| `SERVER_NAME` | hostname | Nom du serveur affiché |
| `PM2_BIN` | pm2 | Chemin pm2 si absent du PATH |
| `TRUST_PROXY` | false | `1` ou `loopback` si reverse proxy (nginx) |
| `SECURE_COOKIE` | 0 | `1` si HTTPS/TLS terminé par proxy |


## Sécurité
- N'expose JAMAIS ce panel directement sur Internet sans HTTPS + reverse proxy.
- Recommandé : accès via VPN (Tailscale, WireGuard).
- Change le mot de passe par défaut.


## Licence
MIT


## Contrôle système (toggles Serveur)

Les toggles **UFW** / **Fail2ban** dans le panneau exécutent de vraies commandes via `sudo` sans mot de passe.


### Configuration requise

Pour que les toggles fonctionnent, ajoute une règle **sudoers ciblée** :

```bash
sudo visudo -f /etc/sudoers.d/h0zelpanel
```

Copie cette ligne (remplace `hozel` par **ton utilisateur** : `$(whoami)` ) :

```
hozel ALL=(root) NOPASSWD: /usr/sbin/ufw enable, /usr/sbin/ufw disable, /usr/sbin/ufw --force enable, /usr/sbin/ufw status, /usr/bin/systemctl start fail2ban, /usr/bin/systemctl stop fail2ban, /usr/bin/systemctl is-active fail2ban, /usr/bin/systemctl start unattended-upgrades, /usr/bin/systemctl stop unattended-upgrades, /usr/bin/systemctl is-active unattended-upgrades, /usr/sbin/reboot, /usr/sbin/poweroff, /usr/bin/systemctl restart systemd-timesyncd, /usr/sbin/sysctl vm.drop_caches=3
```

### Commandes autorisées

| Toggle | Commandes exécutées |
|--------|---------------------|
| **UFW Enable** | `/usr/sbin/ufw enable` |
| **UFW Disable** | `/usr/sbin/ufw disable` |
| **UFW Status** | `/usr/sbin/ufw status` |
| **Fail2ban Start** | `/usr/bin/systemctl start fail2ban` |
| **Fail2ban Stop** | `/usr/bin/systemctl stop fail2ban` |
| **Fail2ban Status** | `/usr/bin/systemctl is-active fail2ban` |
| **Mises à jour** | `/usr/bin/systemctl start unattended-upgrades`, `/usr/bin/systemctl stop unattended-upgrades` |
| **Redémarrer** | `/usr/sbin/reboot` |
| **Arrêter** | `/usr/sbin/poweroff` |
| **Timesync** | `/usr/bin/systemctl restart systemd-timesyncd` |
| **Libérer caches** | `/usr/sbin/sysctl vm.drop_caches=3` |


### Sécurité CRUCIALE

- Ces toggles donnent **le contrôle du pare-feu** à quiconque connaît le mot de passe du panel
- **N'active PAS** cette fonctionnalité si le panel est accessible sur Internet public
- **Requis** : accès uniquement via **VPN** (Tailscale, WireGuard) ou HTTPS + reverse proxy (nginx)
- Utilise un **mot de passe fort** (12+ caractères, unique)
- Après configuration, teste : `sudo -l -U $(whoami)` pour vérifier les permissions


### Vérification

```bash
# Tester la configuration sudoers
sudo visudo -c

# Vérifier tes permissions
sudo -l -U $(whoami)

# Tester une commande
sudo ufw status
```

Si tout fonctionne, les toggles du panel seront opérationnels.


## Récupération (anti-lockout)

Si tu te bloques (whitelist IP, PIN perdu), connecte-toi en SSH et supprime la persistance pour revenir au mot de passe du `.env` :

```bash
rm ~/servdistance/data.json
pm2 restart panel
```

Cela efface : hash du mot de passe UI, PIN, whitelist, config brute-force. Le panel repart sur `PANEL_PASSWORD` du `.env`.
