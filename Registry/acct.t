BEGIN {
foreach (qw(..  .  ../..)) {
    last if -e ($conf = "$_/config");
}
eval { require "$conf"; };
die $@ if $@;
}
use DCE::Registry;

$pgo_item = {
    uuid => $uuid,
    unix_num => 16025,
    quota => -1,
    flags => 0,
    fullname => "DCE-Perl",
};

($rgy, $status) = DCE::Registry->site_open_update($site_name);

$domain = $rgy->domain_person;
$name = "dce_perl"; 
test ++$i, $status;
if($ARGV[0] eq "d") {
    $rgy->pgo_delete($domain, $name); exit();
}

$rgy->pgo_add($domain, $name, $pgo_item);
test ++$i, $status;

$domain = $rgy->domain_group;
$group = "none";
foreach $domain ($rgy->domain_group, $rgy->domain_org) {
    $status = $rgy->pgo_add_member($domain, $group, $name);
}

test ++$i, $status;

$cursor = new DCE::cursor;
$login_name = { 
    pname => $name,
    gname => "none",
    oname => "none",
};

$user_part = {
    gecos => "",
    homedir => "/",
    shell => "/bin/sh",
    passwd_version_number => 0,
    passwd => "-dce_perl-",
    flags => $rgy->acct_user_passwd_valid,
};

$admin_part = {
    good_since_date => time(),
    expiration_date => 0,
};

$admin_part->{flags} |= $rgy->acct_admin_valid;
$admin_part->{flags} |= $rgy->acct_admin_server;
$admin_part->{flags} |= $rgy->acct_admin_client;
$admin_part->{authentication_flags} |= $rgy->acct_auth_forwardable;
$admin_part->{authentication_flags} |= $rgy->acct_auth_renewable;
$admin_part->{authentication_flags} |= $rgy->acct_auth_tgt;

$key_parts = $rgy->acct_key_person;

$caller_key = ""; #admin's password
$new_key = "";    #new user's password

$new_keytype = $rgy->sec_passwd_des;

($key_parts,$new_key_version,$status) =
    $rgy->acct_add($login_name, $key_parts, $user_part, $admin_part, 
		   $caller_key, $new_key, $new_keytype);

#print "add: $key_parts,$new_key_version\n";
test ++$i, $status;

$set_passwd = 0;
$user_part->{shell} = "/bin/csh";
($key_parts,$new_key_version,$status) =
    $rgy->acct_replace_all($login_name, $key_parts, $user_part, 
			   $admin_part, $set_passwd, 
			   $caller_key, $new_key, $new_keytype);

#print "replace all: $key_parts,$new_key_version\n";
test ++$i, $status;


#$login_name = { pname => $name };
($id_sid, $unix_sid, $user_part, $admin_part, $status) = 
    $rgy->acct_lookup($login_name, $cursor);

test ++$i, $status;
for ($id_sid, $unix_sid, $user_part, $admin_part, $login_name) {
    #phash $_;
}

$status = $rgy->acct_delete($login_name);
test ++$i, $status;

$status = $rgy->pgo_delete($rgy->domain_person, $name);

test ++$i, $status;


__END__

$new_login_name = { 
    pname => "meandperl",
    gname => "none",
    oname => "none",
};
$key_parts = $rgy->acct_key_person;
($new_key_parts, $status) = 
    $rgy->acct_rename($login_name, $new_login_name, $key_parts);

test ++$i, $status;

($new_key_parts, $status) = 
    $rgy->acct_rename($new_login_name, $login_name, $key_parts);

test ++$i, $status;








