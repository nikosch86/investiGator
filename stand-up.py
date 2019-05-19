#!/usr/bin/env python3
import os.path
from os.path import expanduser
from pprint import pprint
import secrets
import sys, os, stat, signal, time
import json, base64, hashlib
import argparse
import coloredlogs, logging

logger = logging.getLogger(__name__)

argparser = argparse.ArgumentParser()
argparser.add_argument("--target", default='digitalocean', help="which provider to use", choices=['digitalocean', 'gcloud'])
argparser.add_argument("--digitalocean-api-key", help="API key for digitalocean")
argparser.add_argument("--gcloud-api-key-file", help="API key file for GCloud")
argparser.add_argument("--gcloud-project-id", help="Project ID for GCloud")
argparser.add_argument("--name", help="slug name", default='investig')
argparser.add_argument("--region", help="region or zone", default='random')
argparser.add_argument("--size", help="slug size or machine type", default='2gb')
argparser.add_argument("--image", help="slug image", default='ubuntu-16-04-x64')
argparser.add_argument("--user", help="username to use for ssh connection", default='root')
argparser.add_argument("--ssh-port", help="port to use for ssh connection", default=22, type=int)
argparser.add_argument("--ssh-connection-tries", help="how many times to try to establish ssh connection", default=30, type=int)
argparser.add_argument("--tool", help="additonal tools to install", action='append')
argparser.add_argument("--repo", help="additonal repos to install", action='append')
argparser.add_argument("--vpn", help="vpn service to install", action='append', choices=['ipsec', 'openvpn', 'shadowsocks'])
argparser.add_argument("--force", help="overwrite existing incstances", action='store_true')
argparser.add_argument("--destroy", help="destroy existing incstances", action='store_true')
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
    if args.target == 'digitalocean':
        try:
            droplet
            if droplet.id != None:
                logger.critical("calling destroy() on instance id {}".format(droplet.id))
                droplet.destroy()
        except NameError:
            logger.debug('no instance has been created yet')
    elif args.target == 'gcloud':
        try:
            operation_create
            logger.critical("calling delete() on instance name {}".format(config['name']))
            operation = gce_manager.instances().delete(project=config['gcloud_project_id'], zone=config['region'], instance=config['name']).execute()
            gcloud_wait(gce_manager, config['region'], operation['name'])
        except NameError:
            logger.debug('no instance has been created yet')
    try:
        addKey
        logger.critical("calling destroy() on added ssh key object fingerprint {} and name {}".format(addKey.fingerprint, addKey.name))
        addKey.destroy()
    except NameError:
        pass

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

try:
    from google.oauth2 import service_account
    import googleapiclient.discovery
except ImportError:
    cleanup_and_die("please install the gcloud module: 'pip install -U google-api-python-client'")

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
        cleanup_and_die("the private key '{}' does not seem to be an RSA key in PEM and can not be supported (use 'ssh-keygen -t rsa -m pem')".format(config['ssh_private_key']))
else:
    cleanup_and_die("missing private key")

if os.getenv('DIGITALOCEAN_API_KEY', False) and not args.digitalocean_api_key:
    logger.info('using digitalocean api key from environment')
    cloudkeys['digitalocean'] = os.getenv('DIGITALOCEAN_API_KEY', False)
elif args.digitalocean_api_key:
    logger.debug("using digitalocean api key from arguments")
    cloudkeys['digitalocean'] = args.digitalocean_api_key

if os.getenv('GCLOUD_API_KEY_FILE', False) and not args.gcloud_api_key_file:
    logger.info('using GCloud api key file from environment')
    cloudkeys['gcloud'] = os.getenv('GCLOUD_API_KEY_FILE', False)
elif args.gcloud_api_key_file:
    logger.debug("using GCloud api key file from arguments")
    cloudkeys['gcloud'] = args.gcloud_api_key_file

if config['target'] == 'gcloud':
    if config['size'] == argparser.get_default('size'):
        logger.debug('changing default size to "g1-small" to work for gcloud')
        config['size'] = 'g1-small'

logger.info("validating settings")

def gcloud_wait(gce_manager, zone, operation):
    logger.debug("waiting for operation '{}'".format(operation))
    iteration = 1
    while True and iteration <= 60:
        result = gce_manager.zoneOperations().get(project=config['gcloud_project_id'], zone=zone, operation=operation).execute()

        if result['status'] == 'DONE':
            logger.debug("done waiting for operation '{}'".format(operation))
            if 'error' in result:
                raise Exception(result['error'])
            return result

        iteration += 1
        time.sleep(1)

def printProgressBar(iteration, total=16, length = 100, fill = '█'):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
    """
    percent = ("{0:." + str(0) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print('\r%s |%s| %s%% %s' % ('Progress:', bar, percent, 'Complete'), end = '\r')
    # Print New Line on Complete
    if iteration == total:
        print()

def validate_gcloud():
    if not 'gcloud' in cloudkeys:
        cleanup_and_die('can not find GCloud API key file, please supply via CLI, config file or environment variable "GCLOUD_API_KEY"')
    if not config['gcloud_project_id']:
        with open(cloudkeys['gcloud']) as gcloud_json_file:
            gcloud_json = json.load(gcloud_json_file)
            if gcloud_json['project_id']:
                config['gcloud_project_id'] = gcloud_json['project_id']
                logger.info("extraced GCloud project ID from key file")
            else:
                cleanup_and_die("missing GCloud project ID, please look up or create a project in the GCloud console")

    try:
        gc_credentials = service_account.Credentials.from_service_account_file(cloudkeys['gcloud'])
    except FileNotFoundError:
        cleanup_and_die("GCloud API Key file was not found")
    except (UnicodeDecodeError,json.decoder.JSONDecodeError, ValueError):
        cleanup_and_die("GCloud API Key file has to be json format service account credential file")

    gce_manager = googleapiclient.discovery.build('compute', 'v1', credentials=gc_credentials, cache_discovery=False)

    try:
        raw_all_instances = gce_manager.instances().aggregatedList(project=config['gcloud_project_id'], filter='name = "investig"').execute()
    except googleapiclient.errors.HttpError as Message:
        reason = json.loads(Message.content).get('error').get('message')
        if reason.startswith('Failed to find project'):
            cleanup_and_die("GCloud Project not found, please specify full id (e.g. some-name-1234)")
        else:
            cleanup_and_die("Error querying instances, please check project ID and key/service account permissions:\n{}".format(Message))

    printProgressBar(1)

    for key in raw_all_instances['items'].keys():
        if 'warning' in raw_all_instances['items'][key]:
            if raw_all_instances['items'][key]['warning']['code'] == 'NO_RESULTS_ON_PAGE':
                continue
        for instance in raw_all_instances['items'][key]['instances']:
            if instance['name'] == config['name']:
                logger.warning('the requested name "{}" is already taken by an instance in the zone {}'.format(config['name'], key))
                if config['force']:
                    logger.warning('force option is set, calling delete() on existing instance')
                    try:
                        operation = gce_manager.instances().delete(project=config['gcloud_project_id'], zone=key.replace('zones/', ''), instance=config['name']).execute()
                        gcloud_wait(gce_manager, key.replace('zones/', ''), operation['name'])
                    except Exception as Message:
                        cleanup_and_die('got exception trying to delete existing instance: "{}"'.format(Message))
                else:
                    exit(1)

    printProgressBar(2)

    raw_regions = gce_manager.zones().list(project=config['gcloud_project_id']).execute()
    regions = list()
    for region in raw_regions['items']:
        regions.append(region['name'])
    regions.sort()
    if config['region'] == argparser.get_default('region'):
        config['region'] = secrets.choice(regions)
        logger.debug("default region selected, selecting random region '{}'".format(config['region']))

    if not config['region'] in regions:
        cleanup_and_die('the requested zone "{}" is not amongst the available zones\n{}'.format(config['region'], regions))

    printProgressBar(3)

    raw_machine_types = gce_manager.machineTypes().list(project=config['gcloud_project_id'], zone=config['region']).execute()
    machine_types = list()
    machine_types_pretty = ""
    for machine_type in raw_machine_types['items']:
        machine_types.append(machine_type['name'])
        machine_types_pretty += "{}\t\t{}\n".format(machine_type['name'], machine_type['description'])

    if not config['size'] in machine_types:
        cleanup_and_die('the requested machine type "{}" is not amongst the available machine types for this region\n{}'.format(config['size'], machine_types_pretty))

    printProgressBar(4)

    if config['image'] == argparser.get_default('image'):
        logger.debug('selecting ubuntu 16.04 lts as default for gcloud')
        select_image = gce_manager.images().getFromFamily(project='ubuntu-os-cloud', family='ubuntu-1604-lts').execute()
        config['image'] = select_image['name']
    else:
        raw_images_ubuntu = gce_manager.images().list(project='ubuntu-os-cloud').execute()
        # raw_images_debian = gce_manager.images().list(project='debian-cloud').execute()
        images = list()
        for image_ubuntu in raw_images_ubuntu['items']:
            if 'deprecated' in image_ubuntu:
                if image_ubuntu['deprecated']['state'] == 'DEPRECATED':
                    continue
            images.append(image_ubuntu['name'])
        # for image_debian in raw_images_debian['items']:
        #     if 'deprecated' in image_debian:
        #         if image_debian['deprecated']['state'] == 'DEPRECATED':
        #             continue
        #     images.append(image_debian['name'])
        images.sort()
        if config['image'] not in images:
            cleanup_and_die("the requested image '{}' is not amongst the available images\n{}".format(config['image'], images))

    return gce_manager

def validate_digitalocean():
    if not 'digitalocean' in cloudkeys:
        cleanup_and_die('can not find digitalocean api key, please supply via CLI, config file or environment variable "DIGITALOCEAN_API_KEY"')
    do_manager = digitalocean.Manager(token=cloudkeys['digitalocean'])
    try:
        raw_instances = do_manager.get_data("droplets/")
    except (digitalocean.DataReadError,digitalocean.TokenError) as Message:
        cleanup_and_die('got exception connecting to cloud provider "{}"'.format(Message))

    printProgressBar(1)

    instances = list()
    for instance in raw_instances['droplets']:
        instances.append(instance['name'])

    if config['name'] in instances and not config['destroy']:
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

    printProgressBar(2)

    raw_regions = do_manager.get_data("regions/")
    regions = list()
    for region in raw_regions['regions']:
        regions.append(region['slug'])

    if config['region'] == argparser.get_default('region'):
        config['region'] = secrets.choice(regions)
        logger.debug("no region selected, selecting random region '{}'".format(config['region']))

    for region in raw_regions['regions']:
        if region['slug'] == config['region']:
            if not config['size'] in region['sizes']:
                cleanup_and_die('the requested size "{}" is not amongst the available sizes for this region\n{}'.format(config['size'], region['sizes']))

    if not config['region'] in regions:
        cleanup_and_die('the requested region "{}" is not amongst the available regions\n{}'.format(config['region'], regions))

    printProgressBar(3)

    raw_images = do_manager.get_data("images/")
    images = list()
    for image in raw_images['images']:
        images.append(image['slug'])
    if not config['image'] in images:
        cleanup_and_die('the requested image "{}" is not amongst the available images\n{}'.format(config['image'], images))

    return do_manager

printProgressBar(0)
if args.target == 'digitalocean':
    do_manager = validate_digitalocean()
    printProgressBar(4)
    if config['destroy']:
        all_droplets = do_manager.get_all_droplets()
        for droplet in all_droplets:
            if droplet.name == config['name']:
                droplet.destroy()
        cleanup_and_die("destroyed instances, aborting")
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

    printProgressBar(5)
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
    printProgressBar(6)
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
    printProgressBar(7)
    try:
        addKey
        logger.critical("calling destroy() on added ssh key object fingerprint {} and name {}".format(addKey.fingerprint, addKey.name))
        addKey.destroy()
    except NameError:
        pass
elif args.target == 'gcloud':
    gce_manager = validate_gcloud()
    printProgressBar(5)
    if config['destroy']:
        # operation = gce_manager.instances().delete(project=config['gcloud_project_id'], zone=config['region'], instance=config['name']).execute()
        # gcloud_wait(gce_manager, operation['name'])
        cleanup_and_die("destroyed instances, aborting")

    try:
        check_image = gce_manager.images().get(project='ubuntu-os-cloud', image=config['image']).execute()
    except Exception as Message:
        cleanup_and_die('image invalid: "{}"\nvalid images:\n'.format(Message, images))

    printProgressBar(6)

    source_disk_image = check_image['selfLink']
    logger.info("creating instance")
    machine_type = "zones/{}/machineTypes/{}".format(config['region'], config['size'])
    instance_config = {
        'name':         config['name'],
        'machineType':  machine_type,
        'disks': [
            {
                'boot': True,
                'autoDelete': True,
                'initializeParams': {
                    'sourceImage': source_disk_image,
                }
            }
        ],
        # Specify a network interface with NAT to access the public
        # internet.
        'networkInterfaces': [{
            'network': 'global/networks/default',
            'accessConfigs': [
                {'type': 'ONE_TO_ONE_NAT', 'name': 'External NAT'}
            ]
        }],
        # Allow the instance to access cloud storage and logging.
        'serviceAccounts': [{
            'email': 'default',
            'scopes': [
                'https://www.googleapis.com/auth/devstorage.read_write',
                'https://www.googleapis.com/auth/logging.write'
            ]
        }],
        'metadata': {
            'items': [{
                'key': 'ssh-keys',
                'value': 'root:ssh-rsa '+pKey.get_base64()+' root'
            }]
}
    }
    printProgressBar(7)
    operation_create = gce_manager.instances().insert(project=config['gcloud_project_id'], zone=config['region'], body=instance_config).execute()
    logger.info("waiting for instance to come online")
    status = gcloud_wait(gce_manager, config['region'], operation_create['name'])
    if status['status'] != "DONE":
        cleanup_and_die('something went wrong creating the instance: "{}"'.format(error))
    instance = gce_manager.instances().get(project=config['gcloud_project_id'], zone=config['region'], instance=config['name']).execute()
    instance_ip = instance['networkInterfaces'][0]['accessConfigs'][0]['natIP']
    logger.info("instance with id {} has external IP {}".format(instance['id'], instance_ip))
    printProgressBar(8)
    time.sleep(5)

else:
    cleanup_and_die("no target specified")



ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy)
logger.info("connecting to instance via SSH")

i = 1;
while True:
    try:
        ssh.connect(instance_ip, config['ssh_port'], config['user'], None, pKey, None, 45)
        break
    except paramiko.ssh_exception.AuthenticationException:
        cleanup_and_die("Authentication failed with given private key, please ensure public was properly set")
    except (paramiko.ssh_exception.NoValidConnectionsError):
        logger.debug("connection failed, retrying")
        i += 1
        time.sleep(1)
    # except socket.timeout:
    #     logger.debug("timeout connecting, retrying")
    #     i += 1
    #     time.sleep(1)

    if i >= config['ssh_connection_tries']:
        cleanup_and_die("unable to connect to {} via SSH within time limit of {} seconds".format(instance_ip, config['ssh_connection_tries']))

printProgressBar(9)
logger.info("setting up system")
stdin, stdout, stderr = ssh.exec_command("echo LC_ALL=\"en_US.UTF-8\" >> /etc/default/locale && \
    curl https://get.docker.com | bash")
logger.debug("".join(stdout.readlines()))
if stdout.channel.recv_exit_status() > 0: logger.critical("STDERR of setup command: {}".format(stderr.read()))

printProgressBar(10)

stdin, stdout, stderr = ssh.exec_command("curl -L \"https://github.com/docker/compose/releases/download/{}/docker-compose-Linux-x86_64\" -o /usr/local/bin/docker-compose && \
    chmod +x /usr/local/bin/docker-compose".format(config['compose_version']))
logger.debug("".join(stdout.readlines()))
if stdout.channel.recv_exit_status() > 0: logger.critical("STDERR of setup command: {}".format(stderr.read()))

printProgressBar(11)

if not config['bare']:
    standard_tools="nmap git wpscan exploitdb hashcat hydra gobuster crunch lynx seclists wordlists dirb"
    standard_repos=['magnumripper/JohnTheRipper', 'erwanlr/Fingerprinter', 'laramies/theHarvester']
    stdin, stdout, stderr = ssh.exec_command("curl -fsSL https://archive.kali.org/archive-key.asc | apt-key add - && \
        echo \"deb http://http.kali.org/kali kali-rolling main non-free contrib\" > /etc/apt/sources.list.d/kali.list && \
        echo \"deb-src http://http.kali.org/kali kali-rolling main non-free contrib\" >> /etc/apt/sources.list.d/kali.list && \
        export DEBIAN_FRONTEND=noninteractive; apt-get -q update && \
        apt-get -o Dpkg::Options::=\"--force-overwrite\" -yq install console-setup-linux")
    logger.debug("".join(stdout.readlines()))
    if stdout.channel.recv_exit_status() > 0: logger.critical("STDERR of setup command: {}".format(stderr.read()))

    printProgressBar(12)

    logger.info('installing tools "{}"'.format(standard_tools))
    stdin, stdout, stderr = ssh.exec_command("export DEBIAN_FRONTEND=noninteractive; apt-get -yq install {} zlib1g-dev ruby-dev".format(standard_tools))
    logger.debug("".join(stdout.readlines()))
    if stdout.channel.recv_exit_status() > 0: logger.critical("STDERR of setup command: {}".format(stderr.read()))

    printProgressBar(13)

    for repo in standard_repos:
        logger.info('installing repo "{}"'.format(repo))
        stdin, stdout, stderr = ssh.exec_command("git clone https://github.com/{}.git".format(repo))
        logger.debug("".join(stdout.readlines()))
        if stdout.channel.recv_exit_status() > 0: logger.critical("STDERR of setup command: {}".format(stderr.read()))

    printProgressBar(14)
else:
    logger.debug("not installing standard tools and repos, bare instance")
    config['bare'] = False

if vars(args)['tool']:
    for tool in config['tool']:
        logger.info('installing additional tool "{}"'.format(tool))
        stdin, stdout, stderr = ssh.exec_command("export DEBIAN_FRONTEND=noninteractive; apt-get -yq install {}".format(tool))
        logger.debug("".join(stdout.readlines()))
        if stdout.channel.recv_exit_status() > 0: logger.critical("STDERR of setup command: {}".format(stderr.read()))
    config['tool'] = False

if vars(args)['repo']:
    for repo in config['repo']:
        logger.info('installing additional repo "{}"'.format(repo))
        stdin, stdout, stderr = ssh.exec_command("git clone https://github.com/{}.git".format(repo))
        logger.debug("".join(stdout.readlines()))
        if stdout.channel.recv_exit_status() > 0: logger.critical("STDERR of setup command: {}".format(stderr.read()))
    config['repo'] = False

printProgressBar(15)

if vars(args)['vpn']:
    for vpn in config['vpn']:
        logger.info('installing vpn service {}'.format(vpn))

        if vpn == 'ipsec':
            ssh.exec_command("mkdir -p /root/vpn")
            sftp = ssh.open_sftp()
            sftp.put(ipsec_vpn_compose, "/root/vpn/"+ipsec_vpn_compose)
            sftp.close()
            stdin, stdout, stderr = ssh.exec_command("cd /root/vpn && /usr/local/bin/docker-compose -f {} up -d".format(ipsec_vpn_compose))
            logger.debug("".join(stdout.readlines()))
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
            logger.debug("".join(stdout.readlines()))
            if stdout.channel.recv_exit_status() > 0: logger.critical("STDERR of setup command: {}".format(stderr.read()))
            print("ShadowSocks Server set up at {}, on the client install using pip 'pip install shadowsocks'".format(instance_ip))
            print("\n# sslocal -s {} -p {} -k {}\n".format(instance_ip, 8388, shadowsocks_password))
        #
        # if vpn == 'openvpn':


ssh.close()
write_config(config, configfile)
printProgressBar(16)
print("use this command to interact with droplet")
print("ssh -o StrictHostKeyChecking=no -p{} -i {} {}@{}".format(config['ssh_port'], config['ssh_private_key'], config['user'], instance_ip))
