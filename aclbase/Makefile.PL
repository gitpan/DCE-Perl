use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
require "../config";

WriteMakefile(
    %$MM_DCE,
    'NAME'	=> 'DCE::aclbase',
    'VERSION_FROM' => 'aclbase.pm', # finds $VERSION
);
