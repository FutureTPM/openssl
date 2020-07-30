#! /usr/bin/env perl
# Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec;
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

setup("test_nttru");

plan tests => 6;

require_ok(srctop_file('test','recipes','tconversion.pl'));

ok(run(test(["nttru_test"])), "running nttrutest");

ok(run(app([ 'openssl', 'nttru', '-check', '-in', srctop_file('test', 'testnttru.pem'), '-noout'])), "nttru -check");

 SKIP: {
     skip "Skipping nttru conversion test", 5
	 if disabled("nttru");

     subtest 'nttru conversions -- private key' => sub {
	 tconversion("nttru", srctop_file("test","testnttru.pem"));
     };
     subtest 'nttru conversions -- private key PKCS#8' => sub {
	 tconversion("nttru", srctop_file("test","testnttru.pem"), "pkey");
     };
     subtest 'nttru conversions -- public key' => sub {
	 tconversion("nttru", srctop_file("test","testnttrupub.pem"), "nttru",
         "-pubin", "-pubout");
     };
}
