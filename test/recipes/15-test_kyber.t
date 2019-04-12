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

setup("test_kyber");

plan tests => 6;

require_ok(srctop_file('test','recipes','tconversion.pl'));

ok(run(test(["kyber_test"])), "running kybertest");

ok(run(app([ 'openssl', 'kyber', '-check', '-in', srctop_file('test', 'testkyber.pem'), '-noout'])), "kyber -check");

 SKIP: {
     skip "Skipping kyber conversion test", 5
	 if disabled("kyber");

     subtest 'kyber conversions -- private key' => sub {
	 tconversion("kyber", srctop_file("test","testkyber.pem"));
     };
     subtest 'kyber conversions -- private key PKCS#8' => sub {
	 tconversion("kyber", srctop_file("test","testkyber.pem"), "pkey");
     };
     subtest 'kyber conversions -- public key' => sub {
	 tconversion("kyber", srctop_file("test","testkyberpub.pem"), "kyber",
         "-pubin", "-pubout");
     };
}
