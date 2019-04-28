#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

ALL_TESTS="loopback_test"
NUM_NETIFS=1
source tc_common.sh
source lib.sh

h1_create()
{
	simple_if_init $h1 192.0.2.1/24 198.51.100.1/24
	tc qdisc add dev $h1 clsact
}

h1_destroy()
{
	tc qdisc del dev $h1 clsact
	simple_if_fini $h1 192.0.2.1/24 198.51.100.1/24
}

loopback_test()
{
	RET=0

	tc filter add dev $h1 ingress protocol arp pref 1 handle 101 flower \
		skip_hw arp_op reply arp_tip 192.0.2.1 action drop

	$MZ $h1 -c 1 -t arp -q

	tc_check_packets "dev $h1 ingress" 101 1
	check_fail $? "Matched on a filter without loopback setup"

	ethtool -K $h1 loopback on
	check_err $? "Failed to enable loopback"

	$MZ $h1 -c 1 -t arp -q

	tc_check_packets "dev $h1 ingress" 101 1
	check_err $? "Did not match on filter with loopback"

	ethtool -K $h1 loopback off
	check_err $? "Failed to disable loopback"

	$MZ $h1 -c 1 -t arp -q

	tc_check_packets "dev $h1 ingress" 101 2
	check_fail $? "Matched on a filter after loopback was removed"

	tc filter del dev $h1 ingress protocol arp pref 1 handle 101 flower

	log_test "loopback"
}

setup_prepare()
{
	h1=${NETIFS[p1]}
	h1mac=$(mac_get $h1)

	vrf_prepare

	h1_create
}

cleanup()
{
	pre_cleanup

	h1_destroy

	vrf_cleanup
}

trap cleanup EXIT

setup_prepare
setup_wait

tests_run

exit $EXIT_STATUS
