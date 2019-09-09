# investiGator

script to create droplet / instance on digitalocean or google cloud or setup a manually deployed machine  

the minimum configuration (called "bare") comes with docker and docker-compose preinstalled.  
By default the script makes use of the kali repository to install a bunch of useful tools:  
`nmap git wpscan exploitdb hashcat hydra gobuster crunch lynx seclists wordlists dirb wfuzz`  
and repos:  
`magnumripper/JohnTheRipper`, `erwanlr/Fingerprinter`, `laramies/theHarvester`

## tools / repos
supports adding of additonal tools with the `--tool` and repos with the `--repo` switches which can both be specified multiple times.  


## VPN / Proxy services
supports installing additional services such as VPN or proxy with the `--service` switch.  
currently supported are:
- `shadowsocks` create libev based dockerized shadowsocks server
- `ipsec` create dockerized ipsec + user/pass/psk
- `proxy` create dockerized socks5 proxy with user authentication, returns config line for proxychains
- `wireguard` install kernel modules and bootstrap wireguard configuration
- `ssh-pivot` create dockerized ssh server with random credentials to pivot or tunnel through, returns config line for proxychains

## Wallets
supports installing wallets, for now only monero is supported.  

## help
```
usage: stand-up.py [-h] [--target {digitalocean,gcloud,manual}]
                   [--digitalocean-api-key DIGITALOCEAN_API_KEY]
                   [--gcloud-api-key-file GCLOUD_API_KEY_FILE]
                   [--gcloud-project-id GCLOUD_PROJECT_ID]
                   [--instance-ip INSTANCE_IP] [--name NAME] [--region REGION]
                   [--size SIZE] [--image IMAGE] [--user USER]
                   [--ssh-port SSH_PORT]
                   [--ssh-connection-tries SSH_CONNECTION_TRIES] [--tool TOOL]
                   [--repo REPO]
                   [--service {ipsec,proxy,shadowsocks,wireguard,ssh-pivot}]
                   [--wallet {monero}] [--force] [--destroy] [--bare]
                   [--compose-version COMPOSE_VERSION] [--verbose] [--quiet]
                   [--ssh-private-key SSH_PRIVATE_KEY] [--create-private-key]

optional arguments:
  -h, --help            show this help message and exit
  --target {digitalocean,gcloud,manual}, -t {digitalocean,gcloud,manual}
                        which provider to use (default: digitalocean)
  --digitalocean-api-key DIGITALOCEAN_API_KEY
                        API key for digitalocean
  --gcloud-api-key-file GCLOUD_API_KEY_FILE
                        API key file for GCloud
  --gcloud-project-id GCLOUD_PROJECT_ID
                        Project ID for GCloud (default: first available
                        project id)
  --instance-ip INSTANCE_IP
                        Instance IP if manual mode is used
  --name NAME, -n NAME  slug name (default: investig)
  --region REGION, -r REGION
                        region or zone (default: selects random region/zone)
  --size SIZE, -s SIZE  slug size or machine type (default: 2gb)
  --image IMAGE         slug image (default: ubuntu-16-04-x64)
  --user USER, -u USER  username to use for ssh connection (default: root)
  --ssh-port SSH_PORT   port to use for ssh connection (default: 22)
  --ssh-connection-tries SSH_CONNECTION_TRIES
                        how many times to try to establish ssh connection
                        (default: 30)
  --tool TOOL           additonal tools to install
  --repo REPO           additonal repos to install
  --service {ipsec,proxy,shadowsocks,wireguard,ssh-pivot}
                        service to install
  --wallet {monero}     wallet to install
  --force               overwrite existing incstances
  --destroy             destroy existing incstances
  --bare, -b            create bare instance
  --compose-version COMPOSE_VERSION
                        compose version (default: 1.24.1)
  --verbose, -v
  --quiet, -q           only display errors and IP
  --ssh-private-key SSH_PRIVATE_KEY, -i SSH_PRIVATE_KEY
                        SSH key to access instance (default:
                        /Users/niko/.ssh/id_rsa)
  --create-private-key  create ssh key to access instance
  ```
