# investiGator

An Ansible playbook that **provisions** a throwaway cloud VM (or targets a
machine you already have) and **configures** it as a pentest / VPN / proxy box —
Docker, the Kali pentest toolset, wallets, and a choice of tunnelling services.

This is the Ansible rewrite of the original `stand-up.py` CLI. Everything the
script did over SSH is now expressed as idempotent roles, and instance creation
is handled by each provider's official Ansible collection.

## Supported providers

| `target`       | Provisioning module                         | Credentials (env var)        |
|----------------|---------------------------------------------|------------------------------|
| `digitalocean` | `community.digitalocean.digital_ocean_droplet` | `DIGITALOCEAN_API_KEY`    |
| `gcloud`       | `google.cloud.gcp_compute_instance`         | `GCP_PROJECT`, `GCP_SERVICE_ACCOUNT_FILE` |
| `aws`          | `amazon.aws.ec2_instance`                   | standard boto3 chain (`AWS_*`) |
| `hetzner`      | `hetzner.hcloud.server`                     | `HCLOUD_TOKEN`               |
| `vultr`        | `vultr.cloud.instance`                      | `VULTR_API_KEY`              |
| `linode`       | `community.general.linode_v4`               | `LINODE_ACCESS_TOKEN`        |
| `sporestack`   | REST API via `ansible.builtin.uri`          | `SPORESTACK_TOKEN` (pre-funded) |
| `manual`       | none — configure an existing host           | —                            |

## Requirements

```bash
# Ansible collections
ansible-galaxy collection install -r requirements.yml
# Python SDKs for the providers you intend to use (control node)
pip install -r requirements.txt
```

The target host only needs Python 3 and SSH; the `docker` role installs the
Docker SDK for Python there itself.

## Quick start

Provision **and** configure in one shot:

```bash
export DIGITALOCEAN_API_KEY=dop_v1_xxx
ansible-playbook site.yml -e target=digitalocean -e instance_name=recon
```

Configure a machine you already have (no provisioning):

```bash
ansible-playbook site.yml -e target=manual -e instance_ip=203.0.113.10
# or list hosts under the `investigator` group in inventory/hosts.yml and run:
ansible-playbook configure.yml
```

Tear an instance down again:

```bash
ansible-playbook destroy.yml -e target=digitalocean -e instance_name=recon
```

## What gets installed

- **common** – base packages + `en_US.UTF-8` locale.
- **docker** – Docker Engine, CLI, Compose plugin, and the Python SDK.
- **kali** (when `install_kali: true`) – the Kali rolling apt repo, pinned at low
  priority so it can supply pentest tools without replacing the base system.
- **tools** (skipped when `bare: true`) – the standard toolset
  (`nmap git wpscan exploitdb hashcat hydra gobuster crunch lynx seclists
  wordlists dirb wfuzz`) and repos (`magnumripper/JohnTheRipper`,
  `erwanlr/Fingerprinter`, `laramies/theHarvester`) cloned into `/opt`. Add your
  own with `extra_tools` / `extra_repos` (installed even in bare mode).
- **wallets** – set `wallets: [monero]` to install the Monero CLI.
- **services** – set `services: [...]` from `ipsec`, `shadowsocks`, `proxy`,
  `wireguard`, `ssh-pivot`. Each prints its client connection details at the end
  of the run.

## Examples

Bare Hetzner box with a WireGuard tunnel and a SOCKS5 proxy:

```bash
export HCLOUD_TOKEN=xxx
ansible-playbook site.yml \
  -e target=hetzner -e bare=true \
  -e '{"services": ["wireguard", "proxy"]}'
```

Full Kali toolset on AWS (Ubuntu's default login user is `ubuntu`, so escalate
via sudo):

```bash
ansible-playbook site.yml -e target=aws -e ssh_user=ubuntu \
  -e '{"extra_tools": ["nikto"], "wallets": ["monero"]}'
```

## Configuration

All knobs live in `inventory/group_vars/all.yml` and can be overridden with `-e`
(or `-e @vars.yml`). Highlights:

| Variable | Default | Purpose |
|----------|---------|---------|
| `target` | `digitalocean` | which provider/path to use |
| `instance_name` | `investig` | instance name / inventory label |
| `ssh_user` | `root` | login user (use `ubuntu` for AWS, a non-root user for GCP) |
| `ssh_private_key_file` | `~/.ssh/id_rsa` | key used to reach the host |
| `create_ssh_key` | `false` | generate an RSA 4096 keypair if missing |
| `bare` | `false` | skip the standard pentest toolset |
| `install_kali` | `true` | add the Kali repo (required for the standard tools) |
| `extra_tools` / `extra_repos` | `[]` | extra apt packages / GitHub `owner/name` repos |
| `wallets` | `[]` | e.g. `[monero]` |
| `services` | `[]` | any of `ipsec shadowsocks proxy wireguard ssh-pivot` |

Per-provider region/size/image defaults (Ubuntu 22.04, ~2 GB) are grouped at the
bottom of `all.yml` — e.g. `do_region`, `hcloud_server_type`, `aws_instance_type`.

## Provider notes

- **GCP / AWS** block root SSH on their Ubuntu images. Set `ssh_user` to a
  non-root user (`ubuntu` on AWS); the configure play uses `become` to escalate.
  GCP expects a default network to exist in the project (it does by default).
- **AWS** auth uses the standard boto3 chain (env vars / `~/.aws` / profile) by
  default; set `aws_access_key` / `aws_secret_key` to pass keys explicitly. The
  default security group must allow inbound SSH (and the service ports you open).
- **Sporestack** prepays with cryptocurrency, which **cannot be automated**.
  Create and fund a token out of band (e.g. the `sporestack` CLI), then pass it
  as `SPORESTACK_TOKEN`. The launch returns a `machine_id`; pass it back as
  `-e sporestack_machine_id=...` to `destroy.yml`.

## Layout

```
site.yml            # provision + configure
provision.yml       # create/destroy the instance, register it for configuration
configure.yml       # apply the roles to the investigator group
destroy.yml         # tear the instance down
inventory/          # static inventory + group_vars/all.yml (all defaults)
roles/provision/    # one task file per provider, dispatched by `target`
roles/{common,docker,kali,tools,wallets,services}/   # configuration roles
```
