BEGIN {
foreach (qw(..  .  ../..)) {
    last if -e ($conf = "$_/config");
}
eval { require "$conf"; };
die $@ if $@;
}
use DCE::Registry;

($rgy, $status) = DCE::Registry->site_open_update($site_name);
$domain = $rgy->domain_group;
$name = "dce_perl";
$person = "root";

($is_mem,$status) = $rgy->pgo_is_member($domain, $name, $person);
#test ++$i, $status;
print "is_mem $is_mem\n";

$pgo_item = {
   uuid => "",
   unix_num => -1,
   quota => -1,
   flags => 0,
   fullname => "DCE Perl",
};

$status = $rgy->pgo_add($domain, $name, $pgo_item);
test ++$i, $status;

$status = $rgy->pgo_add_member($domain, $name, $person);
test ++$i, $status;

($is_mem,$status) = $rgy->pgo_is_member($domain, $name, $person);
test ++$i, $status;
print "is_mem $is_mem\n";

$status = $rgy->pgo_delete_member($domain, $name, $person);
test ++$i, $status;


$rgy->pgo_delete($domain, $name);

test ++$i, $status;
