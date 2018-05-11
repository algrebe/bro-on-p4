#!/bin/bash

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source $THIS_DIR/../../env.sh

CLI_PATH=$BMV2_PATH/targets/simple_switch/sswitch_CLI
echo
echo
echo
echo "displaying counters [0]"
echo "counter_read request_indirect_counter 0" | $CLI_PATH counter.json 22222
echo "counter_read reply_indirect_counter 0" | $CLI_PATH counter.json 22222
echo "counter_read corrupted_counter 0" | $CLI_PATH counter.json 22222
echo 
