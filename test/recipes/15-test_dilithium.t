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

setup("test_dilithium");

plan tests => 6;

require_ok(srctop_file('test','recipes','tconversion.pl'));

ok(run(test(["dilithium_test"])), "running dilithiumtest");

ok(run(app([ 'openssl', 'dilithium', '-check', '-in', srctop_file('test', 'testdilithium.pem'), '-noout'])), "dilithium -check");

 SKIP: {
     skip "Skipping dilithium conversion test", 5
	 if disabled("dilithium");

     subtest 'dilithium conversions -- private key' => sub {
	 tconversion("dilithium", srctop_file("test","testdilithium.pem"));
     };
     subtest 'dilithium conversions -- private key PKCS#8' => sub {
	 tconversion("dilithium", srctop_file("test","testdilithium.pem"), "pkey");
     };
     subtest 'dilithium conversions -- public key' => sub {
	 tconversion("dilithium", srctop_file("test","testdilithiumpub.pem"), "dilithium",
         "-pubin", "-pubout");
     };
}
