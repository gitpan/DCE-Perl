package DCE::Registry;

use vars qw($VERSION @ISA);
require DynaLoader;
require DCE::rgybase;

@ISA = qw(DynaLoader DCE::rgybase);

$VERSION = '1.01';

#why the heck doesn't this get inherited?
*AUTOLOAD = \&DCE::rgybase::AUTOLOAD;

sub status {$DCE::status}

sub sec_passwd_none{0};
sub sec_passwd_plain{1};
sub sec_passwd_des{2};
sub no_more_entries{387063929}; #for now

bootstrap DCE::Registry;

1;
__END__

=head1 NAME

DCE::Registry - Perl interface to DCE Registry API

=head1 SYNOPSIS

  use DCE::Registry;

  my $rgy = DCE::Registry->site_open($site_name);

=head1 DESCRIPTION

This module provides an OO Perl interface to the DCE Registry API.
The sec_rgy_ prefix has been dropped and methods are invoked via a
blessed registry_context object.


=head1 AUTHOR

Doug MacEachern <dougm@osf.org>

=head1 SEE ALSO

perl(1), DCE::rgybase(3), DCE::Status(3), DCE::Login(3), DCE::UUID(3).

=cut
