
use ExtUtils::MakeMaker;

WriteMakefile (
  NAME => 'DCE-Perl',
  VERSION => '0.14',
  'dist'    => {
      COMPRESS=> 'gzip -9f', SUFFIX=>'gz', 
      POSTOP => 'mv $(DISTNAME)-$(VERSION).tar.gz ../',
  },
);

sub MY::test {
    q(
TEST_VERBOSE=0

test:
	$(FULLPERL) t/TEST $(TEST_VERBOSE)

);
}

