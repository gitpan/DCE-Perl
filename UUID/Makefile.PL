use ExtUtils::MakeMaker;
require "../config";

WriteMakefile
    (
     %$MM, #from config.pl
     NAME => "DCE::UUID",
     VERSION_FROM => "UUID.pm",
);

