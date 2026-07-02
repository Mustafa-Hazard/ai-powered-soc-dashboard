# Phase 2 — Splunk Enterprise, Universal Forwarder & Reverse Tunnel

## Goal

Get logs from the EC2 victim server flowing into a locally-hosted Splunk Enterprise
instance, despite the home network not being reachable from the public internet.

## Components

### 1. Splunk Enterprise (VirtualBox VM)

- VM: `splunk-server`, Ubuntu Server 24.04, Bridged Adapter (gets its own LAN IP)
- Installed Splunk Enterprise to `/opt/splunk`
- Web UI exposed on port `8000`
- Admin login reset during setup after the original account became unusable
  (see Gotchas below)

### 2. Splunk Universal Forwarder (EC2 victim-server)

- Installed to `/opt/splunkforwarder` on the EC2 instance
- Configured to monitor `/var/log/auth.log`:
  ```
  sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log
  ```
- Configured to forward to `localhost:9997` — this only works because of the reverse
  tunnel described below

### 3. The Reverse SSH Tunnel

**Problem:** The Splunk VM sits on a home network with no port forwarding / likely
CGNAT — it can't accept inbound connections from EC2. EC2, however, *is* reachable
from home.

**Solution:** Instead of exposing the home network, the Splunk VM initiates an
**outbound** SSH connection to EC2 and asks EC2 to forward EC2's local port 9997 back
through that same tunnel to the Splunk VM's port 9997:

```bash
ssh -i ~/aws-keys/victim-server-key.pem -R 9997:localhost:9997 ubuntu@<EC2_PUBLIC_IP> -N
```

Once this is running, anything the forwarder on EC2 sends to "localhost:9997" actually
arrives at the Splunk VM's port 9997.

**Critical detail:** This command must be run **from inside an SSH session on the
Splunk VM** (i.e. after `ssh splunkadmin@<splunk-vm-ip>`), not from the WSL host
directly. Running it from WSL breaks the tunnel, because in that case "localhost:9997"
resolves to WSL — which has nothing listening on that port.

## Enabling the Receiver

On the Splunk VM, after Splunk Enterprise is running:

```bash
sudo /opt/splunk/bin/splunk enable listen 9997 -auth admin:<password>
sudo /opt/splunk/bin/splunk display listen -auth admin:<password>
```

Expected output: `Receiving is enabled on port 9997.`

## Verifying the Pipeline End-to-End

From the forwarder side (on EC2):

```bash
sudo /opt/splunkforwarder/bin/splunk list forward-server -auth toxic:<password>
```

Should show `localhost:9997` under **Active forwards**.

From the Splunk web UI (`http://<splunk-vm-ip>:8000`):

```spl
index=* host="ip-172-31-13-183"
```

Time range: All time — should show live `auth.log` events arriving from the EC2 host.

## Gotchas Encountered

- **`splunk enable listen` can report "already exists" while the port is actually
  disabled.** Don't trust that message as confirmation — recheck with `display
  listen`, and if it disagrees, do a full `stop` / `start --run-as-root` cycle.
- **Splunk Enterprise did not reliably auto-start after a VM reboot.** A plain
  `sudo /opt/splunk/bin/splunk start` sometimes silently no-ops. The reliable fix:
  ```bash
  sudo /opt/splunk/bin/splunk start --run-as-root
  ```
- **The original Splunk admin account broke** after a certificate regeneration event —
  the password file existed but Splunk reported "No users exist." Fixed by deleting
  `/opt/splunk/etc/passwd`, seeding a fresh `user-seed.conf` with new admin
  credentials, and restarting.
- **EC2's public IP changes on every stop/start**, which means both the tunnel command
  and the forwarder's connection need the new IP each session. An AWS Elastic IP would
  eliminate this — considered for a future session.
- **.pem key files copied from a Windows-mounted drive (`/mnt/e/...`) keep failing
  permission checks** for SSH, since NTFS doesn't preserve Linux permission bits.
  Fix: always copy `.pem` files into the actual WSL/VM filesystem (`~/aws-keys/`) and
  `chmod 600` there.

## Outcome

Confirmed working end-to-end: `auth.log` on EC2 → Universal Forwarder → reverse SSH
tunnel → Splunk Enterprise → searchable in the Splunk web UI.
