use ExtUtils::MakeMaker;
require "../config";

WriteMakefile (
     %$MM_DCE, #from config
     NAME => "DCE::ACL",
     VERSION_FROM => "ACL.pm",
);

