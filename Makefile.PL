
use ExtUtils::MakeMaker;

WriteMakefile (
  NAME => 'DCE-Perl',
  VERSION => '0.11',
  'dist'    => {COMPRESS=> 'gzip -9f', SUFFIX=>'gz', 
  	        POSTOP => 'mv $(DISTNAME)-$(VERSION).tar.gz ../'
		},
);
