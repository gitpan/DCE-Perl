BEGIN {
foreach (qw(..  .  ../..)) {
    last if -e ($conf = "$_/config");
}
eval { require "$conf"; };
die $@ if $@;
}

use DCE::Registry;

($rgy, $status) = DCE::Registry->site_bind($site_name);
$rgy->create_cursor($cursor);

$name = "root";
$login_name = { pname => $name };

($id_sid, $unix_sid, $user_part, $admin_part,$status) = 
    $rgy->acct_lookup($login_name, $cursor);

test ++$i, $status;
for ($id_sid, $unix_sid, $user_part, $admin_part, $login_name) {
    phash $_;
}

$uuid = $admin_part->{last_changer}->{principal};
$cursor->reset;

($pgo_item, $pgo_name, $status) = 
    $rgy->pgo_get_by_id($domain, $scope, $uuid, $allow_alias, $cursor);

phash $pgo_item;
print "$pgo_name $pgo_item->{unix_num}\n";
