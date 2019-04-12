#! /usr/bin/env perl
# Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
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

setup("test_genkyber");

plan tests => 6;

ok(run(app([ 'openssl', 'genkyber', '-out', 'genkybertest.pem', 2])),
   "genkyber mode=2");
ok(run(app([ 'openssl', 'kyber', '-check', '-in', 'genkybertest.pem', '-noout'])),
   "kyber -check");
ok(run(app([ 'openssl', 'genkyber', '-out', 'genkybertest.pem', 3])),
   "genkyber mode=3");
ok(run(app([ 'openssl', 'kyber', '-check', '-in', 'genkybertest.pem', '-noout'])),
   "kyber -check");
ok(run(app([ 'openssl', 'genkyber', '-out', 'genkybertest.pem', 4])),
   "genkyber mode=4");
ok(run(app([ 'openssl', 'kyber', '-check', '-in', 'genkybertest.pem', '-noout'])),
   "kyber -check");
