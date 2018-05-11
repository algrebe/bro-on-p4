#!/bin/bash

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source $THIS_DIR/../../env.sh

CLI_PATH=$BMV2_PATH/targets/simple_switch/arp_CLI
$CLI_PATH counter.json 22222
