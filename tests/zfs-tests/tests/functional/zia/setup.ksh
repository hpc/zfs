#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or https://opensource.org/licenses/CDDL-1.0.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright (c) 2021 by Lawrence Livermore National Security, LLC.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/zia/zia.kshlib
verify_runnable "global"

# dpusm needs to be loaded before ZFS
lsmod | grep dpusm > /dev/null
ret="$?"
(( "${ret}" != "0" )) && log_unsupported "dpusm not loaded"

# unload the software provider if the test starts with it loaded
lsmod | grep "${PROVIDER_MODULE}" > /dev/null
ret="$?"
(( "${ret}" == "0" )) && log_must rmmod "${PROVIDER_MODULE}"

log_must default_zpool
log_must load_provider

log_pass
