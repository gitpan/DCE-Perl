BEGIN {
foreach (qw(..  .  ../..)) {
    last if -e ($conf = "$_/config");
}
eval { require "$conf"; };
die $@ if $@;
}
use DCE::Registry;

($rgy, $status) = DCE::Registry->site_bind($site_name);
$org = "";

($policy_data, $status) = $rgy->plcy_get_effective($org);

test ++$i, $status;
phash $policy_data;

($policy_data, $status) = $rgy->plcy_get_info($org);

test ++$i, $status;
phash $policy_data;

$status = $rgy->plcy_set_info($org, $policy_data);

test ++$i, $status;
