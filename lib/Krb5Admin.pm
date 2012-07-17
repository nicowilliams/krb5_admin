#
# Blame: "Roland C. Dowdeswell" <elric@imrryr.org>

package Krb5Admin;

use Krb5Admin::C;

use strict;
use warnings;

our @KHARON_RW_SC_EXPORT = qw/	bind_host
				bootstrap_host_key
				change
				change_passwd
				create
				create_bootstrap_id
				create_host
				create_user
				disable
				enable
				generate_ecdh_key1
				insert_hostmap
				insert_ticket
				master
				modify_host
				remove 
				remove_host
				remove_hostmap
				remove_ticket
				reset_passwd
			     /;

our @KHARON_RO_SC_EXPORT = qw/	query	/;

our @KHARON_RO_AC_EXPORT = qw/	fetch
				fetch_tickets
				list
				listpols
				mquery
				query_host
				query_hostmap
				query_ticket
			     /;

sub KHARON_MASTER {
	my $fh = IO::File->new('/etc/krb5/master', 'r');
	if (!defined($fh)) {
		die "Can't open /etc/krb5/master: $!\n";
	}

	my $master = <$fh>;
	chomp($master);

	return $master;
}

sub new {
	my ($isa, %args) = @_;
	my %self;

	$self{ctx} = Krb5Admin::C::krb5_init_context();

	bless(\%self, $isa);
}

sub genkeys_from_passwd {
	my ($ctx, $princ, $kvno, $passwd, @etypes) = @_;
	my @keys;

	for my $etype (@etypes) {
		my $key = Krb5Admin::C::string_to_key($ctx, $etype,
		    $passwd, $princ);

		$key->{princ} = $princ;
		$key->{kvno}  = $kvno;

		push(@keys, $key);
	}

	return @keys;
}

sub genkeys {
	my ($self, $operation, $princ, $kvno, @etypes) = @_;
	my $ctx = $self->{ctx};

	my ($secret, $public) = @{Krb5Admin::C::curve25519_pass1($ctx)};

	#
	# In a ``normal'' usage, $self->generate_ecdh_key1() will be
	# an RPC to the KDC from which we obtain the ECDH public key.

	my $hispublic = $self->generate_ecdh_key1($operation, $princ);

	#
	# We then use the curve25519_pass2() to generate the keys which we
	# will share with the KDC:

	my $passwd = Krb5Admin::C::curve25519_pass2($ctx, $secret, $hispublic);

	#
	# our curve25519 algorithm just computes a passwd.  We now need to
	# change it into a set of keys which is part of our expected return
	# value.

	my @keys = genkeys_from_passwd($ctx, $princ, $kvno, $passwd, @etypes);

	return {sharedsecret => $passwd, keys => \@keys, public => $public};
}

sub regenkeys {
	my ($self, $gend, $princ) = @_;
	my $ctx = $self->{ctx};

	my $passwd = $gend->{sharedsecret};
	my $kvno   = $gend->{keys}->[0]->{kvno};
	my @etypes = map { $_->{enctype} } @{$gend->{keys}};

	my @keys = genkeys_from_passwd($ctx, $princ, $kvno, $passwd, @etypes);

	return {
		sharedsecret	=> $gend->{sharedsecret},
		public		=> $gend->{public},
		keys		=> \@keys,
	};
}

1;

__END__

=head1 NAME

Krb5Admin - manipulate a Kerberos DB

=head1 SYNOPSIS

	use Krb5Admin;

	my $kmdb = Krb5Admin::KerberosDB->new();

=head1 DESCRIPTION

=head1 CONSTRUCTOR

This is a base class with a basic constructor.  It is not intended to
be used for much except as a base class for Krb5Admin::KerberosDB and
Krb5Admin::Client.

=over 4

=item new(ARGS)

Creates a new "Krb5Admin::KerberosDB" object.  ARGS is a hash which
is simply ignored.

=back

=head1 METHODS

=over 4

=item $kmdb->master()

Will ensure that the master DB is being modified.

=item $kmdb->genkeys()

Generates keys to be installed in a local keytab.  The resultant
keys can then be instantiated in the Kerberos DB with a call to
either create() or change().  genkeys() returns a hash reference
containing two values: keys and publickey.  keys is used to write
the keytab and publickey must be passed to the call to create() or
change().  The calling pattern is as follows:

	my $princ = <the principal>;
	my $kvno  = <the next kvno>;
	my @etypes = (17, 18);

	eval {
		my $gend = $kmdb->genkeys($princ, $kvno, @etypes);

		for my $key (@{$gend->{keys}}) {
			Krb5Admin::C::write_kt($ctx, $kt, $key);
		}

		$kmdb->change($princ, $kvno,
		    public => $gend->{public}, enctypes => \@etypes);
	};
	if ($@) {
		# handle the errors...
	}

approximately.

Internally, genkeys() uses ECDH in the form of curve25519 to
negotiate a shared secret with the code that writes to the Kerberos
database as it may be running in a different process on a different
machine.  Only the ECDH public keys are communicated to generate
the keys on both sides.

It is important to note that we write the generated keys into our
keytab before we call $kmdb->change().  If we do not do things in
this order, the KDC may be vending tickets for the new keys before
our Kerberos servers are able to decrypt them which will cause
connexions to fail.  This can become especially problematic if the
current host crashes before writing keys to the keytab as we do
not want the KDC to ever vend tickets for keys we do not have.
The second part of this issue also affects $kmdb->create().

=item $kmdb->regenkeys(GEND, PRINCIPAL)

Will regenerate keys returned from $kmdb->genkeys() using a
different principal PRINCIPAL.  Other than passing in GEND
which must the the result of a call to $kmdb->genkeys(), it's
usage and return are the same as $kmdb->genkeys().

=item $kmdb->create(PRINCIPAL, [%ARGS])

Creates a principal suitable for use as a service principal.  If
%ARGS is empty, the keys will be selected randomly and enctypes
will be set to the defaults.  If %ARGS contains ``public''---the
public key returned from $kmdb->genkeys(), it will be used to
recreate the keys returned from $kmdb->genkeys.  In this case,
$ARGS{enctype} must also be provided and is an array ref of enctypes.

=item $kmdb->create_user(PRINCIPAL[, PASSWD])

Creates principal suitable for use as a user.  This means that it
will be assigned a password, a password policy and attributes
suitable for use as a user REQUIRES_PRE_AUTH, REQUIRES_PWCHANGE
and DISALLOW_SVR.  The PASSWD argument is optional and if it is
not specified a random password will be selected.  The password
will in either case be returned from the method call.

=item $kmdb->list([GLOB])

Lists the principals in the Kerberos DB.  If supplied, the GLOB
will be applied before the list is returned.  The return will be
an array reference.

=item $kmdb->fetch(PRINCIPAL)

Will fetch the keys associated with PRINCIPAL.  The return value is
a list of hash references containing the following keys: enctype,
timestamp, princ, key, kvno.

=item $kmdb->change(PRINCIPAL, KVNO, %ARGS)

Will change the keys of PRINCIPAL.  If KVNO is defined and greater
than one then change() will throw an exception if the new keys will
not have KVNO as their kvno.  %ARGS can contain either ``keys'' in
which case they will be used directly as the keys or ``public''
and ``enctype'' in which case the keys will be generated as described
in genkeys().

=item $kmdb->change_passwd(PRINCIPAL, PASSWD, OPT)

Will change the password of PRINCIPAL.  If PASSWD is defined then
it will be used as the new password, otherwise a password will be
randomly selected.  OPT is a hash references of options to the
command.  The only option that is currently defined is '+needchange'
which will cause the REQUIRES_PWCHANGE flag to be set on the
principal upon completion.

=item $kmdb->modify(PRINCIPAL, MODS)

TDB.

=item $kmdb->mquery([GLOB, ...])

Will return a set of principals matching the supplied GLOBs.  The return
value will be equivalent to:

	map { $kmdb->query($_) } ($kmdb->list(GLOB))

The function is provided mostly for Krb5Admin::Client's use to reduce the
number of network round trips.

=item $kmdb->query(PRINCIPAL)

Will return a hash reference containing various attributes about
the named principal.  The keys will include: principal, keys,
last_pwd_change, policy, mod_date, pw_expiration, max_life, mod_name,
princ_expire_time, mkvno, kvno, max_renewable_life and attributes.
All of these values will be scalars with the exception of keys and
attributes.  keys is an array reference of hash references containing
keys: enctype, kvno.  It is important to note that keys does not
actually contain the keys---to obtain the keys, the fetch method
must be used.  attributes is an array reference containing the list
of attributes that are set of the principal, e.g. +needchange.

=item $kmdb->enable(PRINCIPAL)

Will remove the -allow_tix flag from PRINCIPAL.

=item $kmdb->disable(PRINCIPAL)

Will set the -allow_tix flag from PRINCIPAL.

=item $kmdb->remove(PRINCIPAL)

Will remove PRINCIPAL.

=back
