use ExtUtils::MakeMaker;
require "../config";

WriteMakefile (
     %$MM_DCE, #from config.pl
     NAME => "DCE::Status",
     VERSION_FROM => "Status.pm",
    INSTALL => '',	       
);

#sub MY::static { "static: \n"; }
#sub MY::dynamic { "dynamic: \n"; }

#sub MY::postamble {
#    my @m;
#    push @m, "install ::\n";
#    push @m, q[$$Config{cp} ./sts.* $(INSTALLPRIVLIB)/DCE];
#    join "", @m;
#}
