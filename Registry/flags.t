use DCE::Registry;

$rgy = "DCE::Registry";
for (qw(acct_admin_valid acct_admin_server acct_admin_client)) {
    $t |= $rgy->$_();
    print "[$t] $_ = ", $rgy->$_(), $/;

}

undef $t;
for (qw(acct_auth_forwardable acct_auth_renewable  acct_auth_tgt
	)) {
    $t |= $rgy->$_();
    print "[$t] $_ = ", $rgy->$_(), $/;

}

