package DCE::Status;
require Exporter;
require DynaLoader;
require Tie::Scalar;

use vars qw($VERSION @ISA @EXPORT_OK);

@ISA = qw(Tie::StdScalar Exporter DynaLoader);
@EXPORT_OK = qw(&error_string);
@EXPORT = qw(&error_inq_text);

$VERSION = '1.00';

bootstrap DCE::Status $VERSION;

1;

__END__

=head1 NAME 

DCE::Status - Make sense of DCE status codes

=head1 SYNOPSIS

    use DCE::Status;
    
    $errstr = error_inq_text($status);

    tie $status => DCE::Status;

=head1 DESCRIPTION



=cut

