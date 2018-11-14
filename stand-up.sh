#!/bin/bash
THIS_DIR="$(dirname "$0")"
source "${THIS_DIR}/functions.sh"
DOCTL=/usr/local/bin/doctl
VPN_COMPOSE="ipsec.yml"
DEFAULT_REGION=ams3
DEFAULT_SLUG=2gb
DEFAULT_NAME=investig
DEFAULT_IMAGE=ubuntu-16-04-x64
DEFAULT_PRIVATE_KEY=~/.ssh/id_rsa
DEFAULT_TOOLS="nmap git"
DEFAULT_REPOS="danielmiessler/SecLists"
REGION=$DEFAULT_REGION
SLUG=$DEFAULT_SLUG
NAME=$DEFAULT_NAME
IMAGE=$DEFAULT_IMAGE
PRIVATE_KEY=$DEFAULT_PRIVATE_KEY
TOOLS=$DEFAULT_TOOLS
REPOS=$DEFAULT_REPOS

function printUsage() {
  echo ""
  echo "Usage: $0 -d -s -u -p -r [-h] [-v]"
  echo ""
  echo "Full description of all options:"
  echo "  -r | --region               : specify region [$DEFAULT_REGION]"
  echo "  -s | --slug                 : specify slug size [$DEFAULT_SLUG]"
  echo "  -n | --name                 : specify droplet name [$DEFAULT_NAME]"
  echo "  -i | --image                : specify image slug [$DEFAULT_IMAGE]"
  echo "  -k | --private-key          : speficy private key location [$DEFAULT_PRIVATE_KEY]"
  echo "  -t | --tools                : specify tools to install [$DEFAULT_SLUG]"
  echo "     | --repos                : specify repos to pull [$DEFAULT_REPOS]"
  echo "  -h | --help                 : Print this menu"
}

while [[ $# -gt 0 ]]; do
  case $1 in
    -h | --help)
    # Print usage and help
    printUsage
    exit 0
    ;;

    -r | --region)
    REGION=$2
    shift
    ;;

    -s | --slug)
    SLUG=$2
    shift
    ;;

    -n | --name)
    NAME=$2
    shift
    ;;

    -i | --image)
    IMAGE=$2
    shift
    ;;

    -k | --private-key)
    PRIVATE_KEY=$2
    shift
    ;;

    -t | --tools)
    TOOLS=$2
    shift
    ;;

    -* | --*)
    # error unknown (long) option $1
    die "Invalid option: $1"
    ;;

    *)
    # Done with options
    break
    ;;
  esac
  shift
done

function cleanup {
  userMessageError "cleanup and die"
  if [ ! -z $DROPLET_ID ]; then
    userMessageError "deleting dropet with name $NAME"
    $DOCTL compute droplet delete $NAME --force
  fi
  exit 1
}
trap cleanup INT

userMessage "checking environment"
$DOCTL auth init >/dev/null 2>&1 || die "doctl needs to be set up to talk to the DO API (brew install doctl)"
type wait-for-it.sh >/dev/null 2>&1 || die "wait-for-it.sh needs to be installed and found in the path (https://github.com/nikosch86/wait-for-it.git)"
type jq >/dev/null 2>&1 || die "jq needs to be installed and found in the path"

userMessage "checking arguments"

if [ $(stat -f %p ${PRIVATE_KEY}) != 100600 ]; then
  printUsage
  die "\nthe permissions for the private key at $PRIVATE_KEY are too loose"
fi

userSubMessage "checking region \"$REGION\""
REGIONS_AVAILABLE=$($DOCTL compute region list --no-header | grep true)
if [ "$(echo $REGIONS_AVAILABLE | egrep "\b$REGION\b" | wc -c)" -lt 1 ]; then
  printUsage
  die "\nthe requested region \"$REGION\" is not amongst the available regions\n$REGIONS_AVAILABLE"
fi

userSubMessage "checking slug size \"$SLUG\""
SLUGS_AVAILABLE=$($DOCTL compute size list --format Slug --no-header)
if [ "$(echo $SLUGS_AVAILABLE | egrep "\b$SLUG\b" | wc -c)" -lt 1 ]; then
  printUsage
  die "\nthe requested slug \"$SLUG\" is not amongst the available slugs\n$SLUGS_AVAILABLE"
fi

userSubMessage "checking slug name \"$NAME\""
NAMES_TAKEN=$($DOCTL compute droplet list --format Name --no-header)
if [ "$(echo $NAMES_TAKEN | egrep "\b$NAME\b" | wc -c)" -gt 0 ]; then
  printUsage
  die "\nthe requested name \"$NAME\" is already taken"
fi

userSubMessage "checking slug image \"$IMAGE\""
IMAGES_AVAILABLE=$($DOCTL compute image list --public --format Slug --no-header | egrep '^\S+$')
if [ "$(echo $IMAGES_AVAILABLE | egrep "\b$IMAGE\b" | wc -c)" -lt 1 ]; then
  printUsage
  die "\nthe requested image slug \"$IMAGE\" is not amongst the available images\n$IMAGES_AVAILABLE"
fi

userMessage "fetching ssh keys"
SSH_KEY_IDS=$($DOCTL compute ssh-key list --format ID --no-header | tr ' |\n' ',' | sed 's/.$//')

# create droplet
userMessage "creating droplet $NAME of $SLUG size with $IMAGE type in region $REGION"
DROPLET_ID=$($DOCTL compute droplet create "$NAME" --size $SLUG --image $IMAGE --region $REGION --ssh-keys $SSH_KEY_IDS --format ID --no-header )
userMessage "created droplet with ID $DROPLET_ID, waiting for it to become ready"
READY_STATUS="active"

while [ "$DROPLET_STATUS" != "$READY_STATUS" ]; do
  sleep 1
  userSubMessage "droplet is in status \"$DROPLET_STATUS\""
  DROPLET_STATUS=$($DOCTL compute droplet get $DROPLET_ID --output json | jq -r '.[] | .status')
done

userMessage "fetching droplet IP"
DROPLET_IP=$($DOCTL compute droplet get $DROPLET_ID --output json | jq -r '.[] | .networks.v4 | .[] | select(.type == "public") | .ip_address')
userMessage "droplet $DROPLET_ID has IP $DROPLET_IP"

SSH_COMMAND="ssh -o StrictHostKeyChecking=no -i ${PRIVATE_KEY} root@${DROPLET_IP}"

userMessage "waiting for ssh to become accessible"
wait-for-it.sh -q -t 60 -h $DROPLET_IP -p 22
sleep 1
userMessage "getting hostkey"
$SSH_COMMAND exit > /dev/null
userMessage "updating system, installing tools ${TOOLS}"
$SSH_COMMAND "echo LC_ALL=\"en_US.UTF-8\" >> /etc/default/locale"
$SSH_COMMAND "export DEBIAN_FRONTEND=noninteractive; apt-get -q update && apt-get -yq upgrade && apt-get -yq install ${TOOLS}" > /dev/null
userMessage "pulling repos ${REPOS}"
for repo in ${REPOS}; do
  $SSH_COMMAND "git pull https://github.com/${repo}.git"
done
userMessage "installing docker using convenience script"
$SSH_COMMAND "curl -fsSL https://get.docker.com | bash" > /dev/null
userMessage "install compose"
$SSH_COMMAND "curl -L "https://github.com/docker/compose/releases/download/1.23.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose"
$SSH_COMMAND "chmod +x /usr/local/bin/docker-compose"
userMessage "putting compose file in place"
$SSH_COMMAND "mkdir -p vpn"
scp -i ${PRIVATE_KEY} ${VPN_COMPOSE} root@${DROPLET_IP}:/root/vpn/

userMessage "starting vpn"
$SSH_COMMAND "docker-compose -f ${VPN_COMPOSE} up -d" > /dev/null
userMessage "VPN Server set up at $DROPLET_IP"
userMessage "use this command to interact with droplet"
userMessage "echo $SSH_COMMAND"
