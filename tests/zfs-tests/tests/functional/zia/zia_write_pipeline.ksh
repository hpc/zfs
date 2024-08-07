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

#
# DESCRIPTION:
#	Z.I.A. Write Pipeline works
#
# STRATEGY:
#   1. Turn each of the offloaded stages on and off
#       1.1. Write data to the zpool
#       1.2. Delete the file
#   2. Disable the provider for the pool and unload the provider
#   3. Do 1. again, but without a provider to make sure Z.I.A. falls back to ZFS properly
#

log_must loop_offloads_and_write
log_must unload_provider
log_must loop_offloads_and_write
log_must load_provider

log_pass
