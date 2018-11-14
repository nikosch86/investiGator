#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
NC='\033[0m'
userMessageError(){
  echo -e "${red}$1${NC}"
}
userMessage(){
  echo -e "${green}$1${NC}"
}
userSubMessage(){
  userMessage "\t$1"
}
die() {
  userMessageError "$1"
  exit 1
}
