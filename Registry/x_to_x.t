BEGIN {
foreach (qw(..  .  ../..)) {
    last if -e ($conf = "$_/config");
}
eval { require "$conf"; };
die $@ if $@;
}

use DCE::Registry;

($rgy, $status) = DCE::Registry->site_bind($site_name);
$domain = $rgy->domain_person();

$unix_num = 0; #root

($uuid, $status) = $rgy->pgo_unix_num_to_id($domain, $unix_num);
print "$unix_num -> $uuid\n";

($name, $status) = $rgy->pgo_unix_num_to_name($domain, $unix_num);
print "$unix_num -> $name\n";

($name, $status) = $rgy->pgo_id_to_name($domain, $uuid);
print "$uuid -> $name\n";

($unix_num, $status) = $rgy->pgo_id_to_unix_num($domain, $uuid);
print "$uuid -> $unix_num\n";


($unix_num, $status) = $rgy->pgo_name_to_unix_num($domain, $name);
print "$name -> $unix_num\n";

($uuid, $status) = $rgy->pgo_name_to_id($domain, $name);
print "$name -> $uuid\n";




