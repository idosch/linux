#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

ALL_TESTS="
	test_set_remote
	test_uc_remote
	test_uc_mc_remote
	test_mc_remote
	test_mc_uc_remote
"
source lib.sh

check_remotes()
{
	local what=$1; shift
	local N=$(bridge fdb sh dev vx | grep 00:00:00:00:00:00 | wc -l)

	((N == 2))
	check_err $? "expected 2 remotes after $what, got $N"
}

# Check FDB default-remote handling across "ip link set".
test_set_remote()
{
	RET=0

	ip_link_add vx up type vxlan id 2000 dstport 4789
	bridge fdb ap dev vx 00:00:00:00:00:00 dst 192.0.2.20 self permanent
	bridge fdb ap dev vx 00:00:00:00:00:00 dst 192.0.2.30 self permanent
	check_remotes "fdb append"

	ip link set dev vx type vxlan remote 192.0.2.30
	check_remotes "link set"

	log_test 'FDB default-remote handling across "ip link set"'
}

fmt_remote()
{
	local addr=$1; shift

	if [[ $addr == 224.* ]]; then
		echo "group $addr"
	else
		echo "remote $addr"
	fi
}

do_test_changelink_remote()
{
	local initial_remote=$1; shift
	local new_remote=$1; shift
	local remote_should_fail=$1; shift
	local dev_should_fail=$1; shift

	ip link set dev vx type vxlan \
		$(fmt_remote $initial_remote) dev d2 2>/dev/null
	check_err_fail $dev_should_fail $? "bound device change"

	ip link set dev vx type vxlan \
		$(fmt_remote $new_remote) dev d1 2>/dev/null
	check_err_fail $remote_should_fail $? "remote change"

	# This should be a NOP change if the above failed as it was supposed to,
	# or else it returns to the initial state. Either way it should pass.
	ip link set dev vx type vxlan \
		$(fmt_remote $initial_remote) dev d1
	check_err $? "Couldn't set remote and bound device back"
}

test_changelink_remote()
{
	local initial_remote=$1; shift
	local new_remote=$1; shift
	local remote_should_fail=$1; shift
	local dev_should_fail=$1; shift

	RET=0

	ip_link_add d1 up type dummy
	ip_link_add d2 up type dummy
	ip_link_add vx up type vxlan dstport 4789 \
		local 192.0.2.1 $(fmt_remote $initial_remote) dev d1 vni 1000

	do_test_changelink_remote $initial_remote $new_remote \
				  $remote_should_fail $dev_should_fail

	if ((remote_should_fail)); then
		ip link set dev vx down
		do_test_changelink_remote $initial_remote $new_remote 0 0
	fi

	log_test "Changing remote on an up VXLAN $initial_remote->$new_remote"
}

test_uc_remote()
{
	test_changelink_remote 192.0.2.3 192.0.2.2 0 0
}

test_mc_remote()
{
	test_changelink_remote 224.0.0.1 224.0.0.2 1 1
}

test_mc_uc_remote()
{
	test_changelink_remote 224.0.0.1 192.0.2.2 1 1
}

test_uc_mc_remote()
{
	test_changelink_remote 192.0.2.2 224.0.0.1 1 0
}

trap defer_scopes_cleanup EXIT

tests_run

exit $EXIT_STATUS
