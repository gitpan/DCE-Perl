use ExtUtils::MakeMaker;
require "../config";

WriteMakefile (
     %$MM_DCE, 
     NAME => "DCE::Login",
     VERSION_FROM => "Login.pm",
);
