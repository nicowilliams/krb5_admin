#!/usr/pkg/bin/perl
#

use Test::More tests => 2;

use Krb5Admin::C;

use strict;
use warnings;

my $ccfile = "./t/krb5cc.$$";
$ENV{KRB5_CONFIG} = './t/krb5.conf';
$ENV{KRB5CCNAME}  = "FILE:$ccfile";

END {
	unlink($ccfile);
}

my  $ctx   = Krb5Admin::C::krb5_init_context();
my  @etypes= Krb5Admin::C::get_as_enctypes($ctx);
our $hndl  = Krb5Admin::C::krb5_get_kadm5_hndl($ctx, 'db:t/test-hdb');
our $realm = Krb5Admin::C::krb5_get_realm($ctx);

#
# XXXrcd: these tests do not actually validate the ticket properly.
#         This will require that we run a KDC and all that.

my $ret;

eval {
	Krb5Admin::C::krb5_deleteprinc($ctx, $hndl,
	    'user@TEST.REALM');
};
eval {
	Krb5Admin::C::krb5_createkey($ctx, $hndl,
	    'user@TEST.REALM');
};

eval {
	Krb5Admin::C::krb5_createkey($ctx, $hndl,
	    'krbtgt/TEST.REALM@TEST.REALM');
};

# it's okay if this has failed: it just means that we've already got
# a TGS key.

$ret = Krb5Admin::C::mint_ticket($ctx, $hndl, 'user', 3600, 7200, \@etypes);
eval {
	Krb5Admin::C::krb5_deleteprinc($ctx, $hndl,
	    'krbtgt/TEST.REALM@TEST.REALM');
	Krb5Admin::C::krb5_deleteprinc($ctx, $hndl,
	    'user@TEST.REALM');
};

ok(!$@) or diag("$@");

eval {
	Krb5Admin::C::init_store_creds($ctx, undef, $ret);
};

ok(!$@) or diag("$@");

exit 0;
