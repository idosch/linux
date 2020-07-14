#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Test that packets are sampled at ingress regardless if they are dropped
# during forwarding or not.
#
# +---------------------------------+
# | H1 (vrf)                        |
# |    + $h1                        |
# |    | 192.0.2.1/24               |
# |    |                            |
# |    |  default via 192.0.2.2     |
# +----|----------------------------+
#      |
# +----|----------------------------------------------------------------------+
# | SW |                                                                      |
# |    + $rp1                                                                 |
# |        192.0.2.2/24                                                       |
# |                                                                           |
# |        198.51.100.2/24                                                    |
# |    + $rp2                                                                 |
# |    |                                                                      |
# +----|----------------------------------------------------------------------+
#      |
# +----|----------------------------+
# |    |  default via 198.51.100.2  |
# |    |                            |
# |    | 198.51.100.1/24            |
# |    + $h2                        |
# | H2 (vrf)                        |
# +---------------------------------+

lib_dir=$(dirname $0)/../../../net/forwarding

ALL_TESTS="
	sample_drop_test
"
NUM_NETIFS=4
source $lib_dir/lib.sh
source $lib_dir/devlink_lib.sh

h1_create()
{
	simple_if_init $h1 192.0.2.1/24

	ip -4 route add default vrf v$h1 nexthop via 192.0.2.2
}

h1_destroy()
{
	ip -4 route del default vrf v$h1 nexthop via 192.0.2.2

	simple_if_fini $h1 192.0.2.1/24
}

h2_create()
{
	simple_if_init $h2 198.51.100.1/24

	ip -4 route add default vrf v$h2 nexthop via 198.51.100.2
}

h2_destroy()
{
	ip -4 route del default vrf v$h2 nexthop via 198.51.100.2

	simple_if_fini $h2 198.51.100.1/24
}

router_create()
{
	ip link set dev $rp1 up
	ip link set dev $rp2 up

	__addr_add_del $rp1 add 192.0.2.2/24
	__addr_add_del $rp2 add 198.51.100.2/24
}

router_destroy()
{
	__addr_add_del $rp2 del 198.51.100.2/24
	__addr_add_del $rp1 del 192.0.2.2/24

	ip link set dev $rp2 down
	ip link set dev $rp1 down
}

setup_prepare()
{
	h1=${NETIFS[p1]}
	rp1=${NETIFS[p2]}

	rp2=${NETIFS[p3]}
	h2=${NETIFS[p4]}

	vrf_prepare
	forwarding_enable

	h1_create
	h2_create
	router_create
}

cleanup()
{
	pre_cleanup

	router_destroy
	h2_destroy
	h1_destroy

	forwarding_restore
	vrf_cleanup
}

sample_drop_test()
{
	tc qdisc add dev $rp1 clsact
	tc filter add dev $rp1 ingress proto all pref 1 handle 101 matchall \
		skip_sw action sample rate 500 group 1

	devlink_trap_stats_test "Sample without drop" "flow_action_sample" \
		$MZ $h1 -c 1000 -d 10msec -a own -b $(mac_get $rp1) \
		-A 192.0.2.1 -B 198.51.100.1 -t udp sp=12345,dp=54321 -p 100 -q

	# Add a blackhole route that will drop packets.
	ip route add blackhole 198.51.100.1/32

	devlink_trap_stats_test "Sample with drop" "flow_action_sample" \
		$MZ $h1 -c 1000 -d 10msec -a own -b $(mac_get $rp1) \
		-A 192.0.2.1 -B 198.51.100.1 -t udp sp=12345,dp=54321 -p 100 -q

	ip route del blackhole 198.51.100.1/32
	tc filter del dev $rp1 ingress proto all pref 1 handle 101 matchall
	tc qdisc del dev $rp1 clsact
}

trap cleanup EXIT

setup_prepare
setup_wait

tests_run

exit $EXIT_STATUS
