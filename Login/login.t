BEGIN {
foreach (qw(..  .  ../..)) {
    last if -e ($conf = "$_/config");
}
eval { require "$conf"; };
die $@ if $@;
}

use DCE::Login;

($pname, $password) = ("dougm", "dougm");

$l = "DCE::Login";
($l, $status) = $l->setup_identity($pname, $l->no_flags);
test ++$i, $status;

($valid, $reset_passwd, $auth_src, $status) = 
    $l->valid_and_cert_ident($password);
test ++$i, $status;

#($valid, $reset_passwd, $auth_src, $status) = 
#    $l->validate_identity($password);
#test ++$i, $status;

#($reset_passwd, $auth_src, $status) = $l->valid_from_keytable($keyfile);
#test ++$i, $status;

($pwent, $status) = $l->get_pwent;
test ++$i, $status;
phash $pwent;

($l, $status) = DCE::Login->get_current_context;
test ++$i, $status;

$exp = $l->get_expiration;
#print "expiration: $exp\n";

$status = $l->refresh_identity;
test ++$i, $status;

($buf,$len_used,$len_needed,$status) = $l->export_context(128);
test ++$i, $status;
#print "[$len_used,$len_needed]$buf\n";

($l, $status) = DCE::Login->import_context($len_needed, $buf);
test ++$i, $status;


$status = $l->release_context;
test ++$i, $status;

#$status = $l->purge_context;
#test ++$i, $status;

#this should fail after releasing the context
#($exp,$status) = $l->get_expiration;
#test ++$i, $status; #sec_login_s_context_invalid
#print "expiration: $exp\n";


__END__
