#!/usr/bin/env python3
import os.path
from os.path import expanduser
import sys, os, stat, signal, time
import json, base64, hashlib
import argparse
import coloredlogs, logging

logger = logging.getLogger(__name__)

argparser = argparse.ArgumentParser()
argparser.add_argument("--target", default='digitalocean', help="which provider to use", choices=['digitalocean'])
argparser.add_argument("--digitalocean-api-key", help="API key for digitalocean")
argparser.add_argument("--name", help="slug name", default='investig')
argparser.add_argument("--region", help="region", default='ams3')
argparser.add_argument("--size", help="slug size", default='2gb')
argparser.add_argument("--image", help="slug image", default='ubuntu-16-04-x64')
argparser.add_argument("--user", help="username to use for ssh connection", default='root')
argparser.add_argument("--ssh-port", help="port to use for ssh connection", default=22, type=int)
argparser.add_argument("--ssh-connection-tries", help="how many times to try to establish ssh connection", default=30, type=int)
argparser.add_argument("--tool", help="additonal tools to install", action='append')
argparser.add_argument("--repo", help="additonal repos to install", action='append')
argparser.add_argument("--vpn", help="vpn service to install", action='append', choices=['ipsec', 'openvpn', 'shadowsocks'])
argparser.add_argument("--force", help="overwrite existing incstances", action='store_true')
argparser.add_argument("--bare", help="create bare instance", action='store_true')
argparser.add_argument("--compose-version", default='1.23.1')
argparser.add_argument("--verbose", "-v", action='count', default=0)
argparser.add_argument("--ssh-private-key", help="ssh key to access instance", default=expanduser("~") + '/.ssh/id_rsa')
args = argparser.parse_args()

levels = [logging.WARNING, logging.INFO, logging.DEBUG]
level = levels[min(len(levels)-1,args.verbose)]
coloredlogs.install(level=level)

cloudkeys = {}
ipsec_vpn_compose = "ipsec.yml"

configfile = expanduser("~") + '/.config/investiGator.json'

def signal_handler(sig, frame):
        cleanup_and_die('Interrupt signal triggered')
signal.signal(signal.SIGINT, signal_handler)
# signal.pause()

def cleanup_and_die(msg):
    try:
        droplet
        if droplet.id != None:
            logger.critical("calling destryoy() on instance id {}".format(droplet.id))
            droplet.destroy()
    except NameError:
        logger.debug('no instance has been created yet')

    logger.critical(msg)
    sys.exit(2)

try:
    import paramiko
except ImportError:
    cleanup_and_die("please install the paramiko module: 'pip install -U paramiko'")

try:
    import digitalocean
except ImportError:
    cleanup_and_die("please install the digitalocean module: 'pip install -U python-digitalocean'")

def write_config(configdict, configfile):
    with open(configfile, 'w') as configfilefd:
        json.dump(configdict, configfilefd, sort_keys=True, indent=2)

def read_config(config_file):
    with open(configfile, 'r') as configfilefd:
        config = json.load(configfilefd)
        return config

def keyToFingerprint(publicKey):
    key = base64.b64decode(publicKey.strip().encode('ascii'))
    fp_plain = hashlib.md5(key).hexdigest()
    return ':'.join(a+b for a,b in zip(fp_plain[::2], fp_plain[1::2]))

if os.path.exists(configfile):
    config = read_config(configfile)
    if not 'cloudkeys' in config:
        config['cloudkeys'] = cloudkeys
    else:
        cloudkeys = config['cloudkeys']
else:
    logger.info('no config file found, assuming defaults')
    config = vars(args)
    config['cloudkeys'] = cloudkeys
    write_config(config, configfile)

config = {**config, **vars(args)}
logger.debug(config)

if os.path.exists(config['ssh_private_key']):
    statr = os.stat(config['ssh_private_key']).st_mode
    if not stat.filemode(statr) == '-rw-------':
        cleanup_and_die('the permissions for the private key at {} are too loose'.format(config['ssh_private_key']))
    try:
        pKey = paramiko.RSAKey.from_private_key_file(config['ssh_private_key'])
    except paramiko.ssh_exception.PasswordRequiredException:
        cleanup_and_die("the private key '{}' requires a password, as of now this is not supported, please us a private key without password".format(config['ssh_private_key']))
    except paramiko.ssh_exception.SSHException:
        cleanup_and_die("the private key '{}' does not seem to be a proper RSA key and can not be supported".format(config['ssh_private_key']))

if os.getenv('DIGITALOCEAN_API_KEY', False) and not args.digitalocean_api_key:
    logger.info('using digitalocean api key from environment')
    cloudkeys['digitalocean'] = os.getenv('DIGITALOCEAN_API_KEY', False)
elif 'digitalocean_api_key' in args:
    cloudkeys['digitalocean'] = args.digitalocean_api_key

def validate_digitalocean():
    if not 'digitalocean' in cloudkeys:
        cleanup_and_die('can not find digitalocean api key, please supply via CLI, config file or environment variable "DIGITALOCEAN_API_KEY"')
    if len(cloudkeys['digitalocean']) != 64:
        cleanup_and_die('the digitalocean API key has to be 64 characters long')
    do_manager = digitalocean.Manager(token=cloudkeys['digitalocean'])
    try:
        raw_instances = do_manager.get_data("droplets/")
    except digitalocean.DataReadError as Message:
        cleanup_and_die('got exception connecting to cloud provider "{}"'.format(Message))

    instances = list()
    for instance in raw_instances['droplets']:
        instances.append(instance['name'])

    if config['name'] in instances:
        logger.warning('the requested name "{}" is already taken'.format(config['name']))
        if config['force']:
            raw_instances = do_manager.get_data("droplets/")
            for instance in raw_instances['droplets']:
                if instance['name'] == config['name']:
                    existing_instance = do_manager.get_droplet(instance['id'])
                    logger.warning('force option is set, calling destroy() on existing instance id {}'.format(existing_instance.id))
                    existing_instance.destroy()
                    break
        else:
            exit(1)

    raw_regions = do_manager.get_data("regions/")
    regions = list()
    for region in raw_regions['regions']:
        regions.append(region['slug'])
        if region['slug'] == config['region']:
            if not config['size'] in region['sizes']:
                cleanup_and_die('the requested size "{}" is not amongst the available sizes for this region\n{}'.format(config['size'], region['sizes']))
    if not config['region'] in regions:
        cleanup_and_die('the requested region "{}" is not amongst the available regions\n{}'.format(config['region'], regions))
    raw_images = do_manager.get_data("images/")
    images = list()
    for image in raw_images['images']:
        images.append(image['slug'])
    if not config['image'] in images:
        cleanup_and_die('the requested image "{}" is not amongst the available images\n{}'.format(config['image'], images))

    return do_manager

if args.target == 'digitalocean':
    logger.info("validating settings")
    do_manager = validate_digitalocean()
    raw_keys = do_manager.get_data("account/keys/")
    keys_fingerprints = list()
    for key in raw_keys['ssh_keys']:
        keys_fingerprints.append(key['fingerprint'])
    if not keyToFingerprint(pKey.get_base64()) in keys_fingerprints:
        logger.info('adding ssh key')
        addKey = digitalocean.SSHKey(token=cloudkeys['digitalocean'],
            name='key-uploaded-by-investiGator',
            public_key='ssh-rsa '+pKey.get_base64()
        )
        addKey.create()

    logger.info("creating instance")
    all_keys = do_manager.get_all_sshkeys()
    droplet = digitalocean.Droplet(
        token=cloudkeys['digitalocean'],
        name=config['name'],
        region=config['region'],
        image=config['image'],
        size_slug=config['size'],
        ssh_keys=all_keys
    )
    droplet.create()
    logger.info("waiting for instance to come online")
    actions = droplet.get_actions()
    for action in actions:
        action.load()
    action.wait()
    droplet.load()
    if droplet.status != 'active':
        cleanup_and_die('something went wrong creating the instance, the status is "{}"'.format(droplet.status))
    instance_ip = droplet.ip_address
    logger.info("instance with id {} has external IP {}".format(droplet.id, instance_ip))

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy)
i = 1;
while True:
    logger.info("connecting to instance via SSH")
    try:
        ssh.connect(instance_ip, config['ssh_port'], config['user'], None, pKey, None, 30)
        break
    except paramiko.ssh_exception.AuthenticationException:
        cleanup_and_die("Authentication failed with given private key, please ensure public was properly set")
    except paramiko.ssh_exception.NoValidConnectionsError:
        logger.debug("connection failed, retrying")
        i += 1
        time.sleep(1)

    if i >= config['ssh_connection_tries']:
        cleanup_and_die("unable to connect to {} via SSH within time limit of {} seconds".format(instance_ip, config['ssh_connection_tries']))

logger.info("setting up system")
stdin, stdout, stderr = ssh.exec_command("echo LC_ALL=\"en_US.UTF-8\" >> /etc/default/locale && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - && \
    add-apt-repository \"deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable\" && \
    export DEBIAN_FRONTEND=noninteractive; apt-get -q update && apt-get -yq upgrade && apt-get -yq install docker-ce")
logger.debug(stdout.read())
if stdout.channel.recv_exit_status() > 0: logger.critical("STDERR of setup command: {}".format(stderr.read()))

stdin, stdout, stderr = ssh.exec_command("curl -L \"https://github.com/docker/compose/releases/download/{}/docker-compose-Linux-x86_64\" -o /usr/local/bin/docker-compose && \
    chmod +x /usr/local/bin/docker-compose".format(config['compose_version']))
logger.debug(stdout.read())
if stdout.channel.recv_exit_status() > 0: logger.critical("STDERR of setup command: {}".format(stderr.read()))

if not config['bare']:
    standard_tools="nmap git wpscan exploitdb hashcat hydra gobuster crunch lynx seclists wordlists dirb"
    standard_repos=['magnumripper/JohnTheRipper', 'erwanlr/Fingerprinter']
    stdin, stdout, stderr = ssh.exec_command("curl -fsSL https://archive.kali.org/archive-key.asc | apt-key add - && \
        echo \"deb http://http.kali.org/kali kali-rolling main non-free contrib\" > /etc/apt/sources.list.d/kali.list && \
        echo \"deb-src http://http.kali.org/kali kali-rolling main non-free contrib\" >> /etc/apt/sources.list.d/kali.list && \
        export DEBIAN_FRONTEND=noninteractive; apt-get -q update && \
        apt-get -o Dpkg::Options::=\"--force-overwrite\" -yq install console-setup-linux && \
        apt-get -yq install {} zlib1g-dev ruby-dev".format(standard_tools))
    logger.debug(stdout.read())
    if stdout.channel.recv_exit_status() > 0: logger.critical("STDERR of setup command: {}".format(stderr.read()))

    for repo in standard_repos:
        logger.info('installing repo "{}"'.format(repo))
        stdin, stdout, stderr = ssh.exec_command("git clone https://github.com/{}.git".format(repo))
        logger.debug(stdout.read())
        if stdout.channel.recv_exit_status() > 0: logger.critical("STDERR of setup command: {}".format(stderr.read()))
else:
    logger.debug("not installing standard tools and repos, bare instance")
    config['bare'] = False

if vars(args)['tool']:
    for tool in config['tool']:
        logger.info('installing additional tool "{}"'.format(tool))
        stdin, stdout, stderr = ssh.exec_command("export DEBIAN_FRONTEND=noninteractive; apt-get -yq install {}".format(tool))
        logger.debug(stdout.read())
        if stdout.channel.recv_exit_status() > 0: logger.critical("STDERR of setup command: {}".format(stderr.read()))
    config['tool'] = False

if vars(args)['repo']:
    for repo in config['repo']:
        logger.info('installing additional repo "{}"'.format(repo))
        stdin, stdout, stderr = ssh.exec_command("git clone https://github.com/{}.git".format(repo))
        logger.debug(stdout.read())
        if stdout.channel.recv_exit_status() > 0: logger.critical("STDERR of setup command: {}".format(stderr.read()))
    config['repo'] = False

if vars(args)['vpn']:
    for vpn in config['vpn']:
        logger.info('installing vpn service {}'.format(vpn))
        if vpn == 'ipsec':
            ssh.exec_command("mkdir -p /root/vpn")
            sftp = ssh.open_sftp()
            sftp.put(ipsec_vpn_compose, "/root/vpn/"+ipsec_vpn_compose)
            sftp.close()
            stdin, stdout, stderr = ssh.exec_command("cd /root/vpn && /usr/local/bin/docker-compose -f {} up -d".format(ipsec_vpn_compose))
            logger.debug(stdout.read())
            if stdout.channel.recv_exit_status() > 0: logger.critical("STDERR of setup command: {}".format(stderr.read()))
            print("IPSec VPN Server set up at "+instance_ip)

        if vpn == 'shadowsocks':
            try:
                import strings
                import secrets
                alphabet = string.ascii_letters + string.digits
                shadowsocks_password = ''.join(secrets.choice(alphabet) for i in range(16))
            except (ImportError, ModuleNotFoundError):
                logger.warning("strings and secrets module not found, falling back to insecure password generation")
                shadowsocks_password = hashlib.sha256(time.asctime().encode('utf-8')).hexdigest()

            stdin, stdout, stderr = ssh.exec_command("docker run -e PASSWORD={} -p8388:8388 -p8388:8388/udp -d shadowsocks/shadowsocks-libev".format(shadowsocks_password))
            logger.debug(stdout.read())
            if stdout.channel.recv_exit_status() > 0: logger.critical("STDERR of setup command: {}".format(stderr.read()))
            print("ShadowSocks Server set up at {}, on the client install using pip 'pip install shadowsocks'".format(instance_ip))
            print("\n# sslocal -s {} -p {} -k {}\n".format(instance_ip, 8388, shadowsocks_password))

ssh.close()
write_config(config, configfile)
print("use this command to interact with droplet")
print("ssh -o StrictHostKeyChecking=no -p{} -i {} {}@{}".format(config['ssh_port'], config['ssh_private_key'], config['user'], instance_ip))
