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
$scope = "";
$test = {
    get_next => 0,
    get_by_name => 0,
    get_by_id => 1,
    get_by_unix_num => 1,
    get_members => 1,
};

{
    #cursors will be destroyed once we leave this block
    #freeing the malloc'd sec_rgy_cursor_t's
    my($next_cursor,$name_cursor);
    $rgy->create_cursor($next_cursor); 
    $rgy->create_cursor($name_cursor);

    while(1) {
	#last;
	$pgo_item = $pgo_name = "";
	($pgo_item, $pgo_name, $status) = 
	    $rgy->pgo_get_next($domain,$scope,$next_cursor);
	
	#last if $status == no_more_entries();
	test ++$i;
	($pgo_item, $status) = 
	    $rgy->pgo_get_by_name($domain,$pgo_name,$name_cursor);
	last unless $test->{get_by_name};
	print "by_name($pgo_name) -> \n";
	phash $pgo_item;
	
	test ++$i;
	last if length $pgo_item->{fullname};
	#<STDIN>;
    }

}

$uuid = $pgo_item->{id}; 
$unix_num = $pgo_item->{unix_num};

{
    last unless $test->{get_by_id};
    my $pgo_item = {};         
    my $pgo_name = "";
    my $cursor;
    $rgy->create_cursor($cursor); 
    ($pgo_item, $pgo_name, $status) = 
	$rgy->pgo_get_by_id($domain, $scope, $uuid, $allow_alias, $cursor);

    print "by_id($uuid) -> $pgo_name\n";
    phash $pgo_item;
}
{
    last unless $test->{get_by_unix_num};
    my $pgo_item = {};         
    my $pgo_name = "";
    my $cursor;
    $rgy->create_cursor($cursor); 
    ($pgo_item, $pgo_name, $status) = 
	$rgy->pgo_get_by_unix_num($domain, $scope, $unix_num, 
				  $allow_alias, $cursor);

    print "by_unix_num($unix_num) -> $pgo_name\n";
    phash $pgo_item;
}

{
    last unless $test->{get_members};
    my $max_members = 5;  
    my $status = 0;
    my $domain = $rgy->domain_group;
    my $name = "none";
    my $cursor;
    $rgy->create_cursor($cursor);
    my $total = 0;
    my($list,$number_supplied,$number_members);

    while(1) { 
	($list,$number_supplied,$number_members,$status) =
	    $rgy->pgo_get_members($domain,$name,$cursor,$max_members);
	$total += $number_supplied;

	last if $status == $rgy->no_more_entries();
	last if $number_members == 0;
	print " [$number_supplied,$number_members,$total]list: @$list\n";
	last if $total >= $number_members;
	#test ++$i;
	#<STDIN>;
    }
}
