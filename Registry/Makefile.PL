use ExtUtils::MakeMaker;
require "../config";

WriteMakefile (
     %$MM_DCE, #from config
     NAME => "DCE::Registry",
     VERSION_FROM => "Registry.pm",
);

