#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Test devlink-trap L2 control functionality over mlxsw. Each registered L2
# control packet trap is tested to make sure it is triggered under the right
# conditions.
#
# +------------------------+                           +----------------------+
# | H1 (vrf)               |                           |             H2 (vrf) |
# |    + $h1               |                           |  + $h2               |
# |    | 192.0.2.1/24      |                           |  | 192.0.2.2/24      |
# |    | 2001:db8:1::1/64  |                           |  | 2001:db8:1::2/64  |
# +----|-------------------+                           +--|-------------------+
#      |                                                  |
# +----|--------------------------------------------------|-------------------+
# | SW |                                                  |                   |
# |    |                                                  |                   |
# |    + $swp1                   BR1 (802.1q)             + $swp2             |
# |                                                                           |
# +---------------------------------------------------------------------------+

lib_dir=$(dirname $0)/../../../net/forwarding

ALL_TESTS="
	stp_test
"
NUM_NETIFS=4
source $lib_dir/tc_common.sh
source $lib_dir/lib.sh
source $lib_dir/devlink_lib.sh

h1_create()
{
	simple_if_init $h1 192.0.2.1/24 2001:db8:1::1/64
}

h1_destroy()
{
	simple_if_fini $h1 192.0.2.1/24 2001:db8:1::1/64
}

h2_create()
{
	simple_if_init $h2 192.0.2.2/24 2001:db8:1::2/64
}

h2_destroy()
{
	simple_if_fini $h2 192.0.2.2/24 2001:db8:1::2/64
}

switch_create()
{
	ip link add dev br0 type bridge mcast_snooping 0 vlan_filtering 1

	ip link set dev $swp1 master br0
	ip link set dev $swp2 master br0

	ip link set dev br0 up
	ip link set dev $swp1 up
	ip link set dev $swp2 up

	tc qdisc add dev $swp1 clsact
}

switch_destroy()
{
	tc qdisc del dev $swp1 clsact

	ip link set dev $swp2 down
	ip link set dev $swp1 down

	ip link del dev br0
}

setup_prepare()
{
	h1=${NETIFS[p1]}
	swp1=${NETIFS[p2]}

	swp2=${NETIFS[p3]}
	h2=${NETIFS[p4]}

	vrf_prepare

	h1_create
	h2_create

	switch_create
}

cleanup()
{
	pre_cleanup

	switch_destroy

	h2_destroy
	h1_destroy

	vrf_cleanup
}

stp_test()
{
	# Drop received STP frames in order to prevent them from being trapped
	# at H2 and counted again.
	tc filter add dev $swp1 ingress proto all pref 1 handle 101 \
		flower skip_hw dst_mac 01:80:c2:00:00:00 action drop

	devlink_trap_stats_test "STP" "stp" $MZ $h1 -c 1 -t bpdu -q

	tc filter del dev $swp1 ingress proto all pref 1 handle 101 flower
}

trap cleanup EXIT

setup_prepare
setup_wait

tests_run

exit $EXIT_STATUS
