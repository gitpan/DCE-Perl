use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
require "../config";

WriteMakefile(
    %$MM_DCE,
    'NAME'	=> 'DCE::rgybase',
    'VERSION_FROM' => 'rgybase.pm', # finds $VERSION
);
