#!/usr/bin/perl

use strict;
use warnings;
use DateTime;
use Date::Parse;
use Net::Subnet;
use Data::Dumper;
use Getopt::Long;
use Chart::Gnuplot;
use Data::Validate::IP qw(is_private_ipv4);
use vars qw ($udp4col $tcp4col $udp6col $tcp6col $linecol $bgcol $yesterday $png_basedir $html_basedir);

$udp4col  = '#b0b0ff';
$tcp4col  = '#00ff00';
$udp6col  = '#ffffff';
$tcp6col  = '#ff0000';
$linecol  = '#c0c0c0';
$bgcol    = '#000000';

$fireplot_basedir = "/var/www/html/fireplot";

# This could be handled much better.
# $timezone = your local timezone if the logs use it.
# $timezone_secs = the same timezone offset in seconds.
# Also change timezone name a few lines down.
$timezone = "+0200";
$timezone_secs = 7200;

# Add your inside networks if you want to log
# external firewall traffic only
my $inside_network = subnet_matcher qw (
    10.0.0.0/8
    172.16.0.0/12
    192.168.0.0/16
    0.0.0.0/32
);

# --yesterday for last day's graphs
# Run this early each day, e.g. 00:10 
GetOptions ("yesterday"  => \$yesterday);

# Change this
my $dt = DateTime->now(
    time_zone => "Europe/Oslo",
);

if ($yesterday) {
    $dt->subtract ( days => 1 );
}

my $today = $dt->ymd;
my $start = $today . ' 00:00:00 +0000';
my $end   = $today . ' 23:59:59 +0000';
my $startofday = str2time ($start);
my $endofday   = str2time ($end);

my $chart = Chart::Gnuplot->new (
    output => "${fireplot_basedir}/fireplot-64-${today}.png",
    title => {
	text => "Firewall activity $today",
	color => $linecol,
    },
    xlabel => {
	text => "Time",
	color => $linecol,
    },
    ylabel => {
	text => "Port",
	color => $linecol,
    },
    timeaxis => "x",
    bg => $bgcol,
    border => {
	sides    => "top, bottom, left, right",
	linetype => 3,
	width    => 2,
	color    => $linecol,
	tmargin  => 10,
	lmargin  => 10,
    },
    xrange => [$startofday, $endofday],
    yrange => [0.5, 65535],
    xtics => {
	labelfmt => '%H:%M',
    },
    ytics => {
	labels => [ 1, 7, 22, 53, 80, 123, 161, 443, 587, 1024, 1433, 3306, 5000, 6881, 10000, 20000, 50000, 65535 ],
	font => 'DroidSans',
	fontsize => 11,
    },
    imagesize => "1.6, 1.0",
    );

# Empty arrays
my @tcp4_pairs = ();
my @udp4_pairs = ();
my @tcp6_pairs = ();
my @udp6_pairs = ();

# Define the upper left and lower right corners
# of the final plot, to calculate where the plots
# will appear.
my $x1 = 88;
my $y1 = 44;
my $x2 = 1128;
my $y2 = 438;
my $yfactor = (($y2 - $y1) / (log (65535)/log(10)));
# print "Y factor: $yfactor\n";

my $xfactor = (($x2 - $x1) / 24);
# print "X factor: $xfactor\n";

# Create an imagemap hash, in which to store information
# for mouse-over
my %imagemap;

# Here you have to create your own regular expression to match your firewall logs
# You must change/modify:
# 1) The path(s) to your log file(s)
# 2) The regular expression(s) to extract the following fields:
#    - date
#    - protocol (udp or tcp)
#    - source IP
#    - source port
#    - destination IP
#    - destination port
# The code will crudely identify whether the IP address
# is an IPv4 or IPv6 address.

open (INPUT, "grep -h corerouter /var/log/logstash/everything.log.1 /var/log/logstash/everything.log |") or die "I failed";
while (my $line = <INPUT>) {
    next if $line =~ /ACK,FIN/;
    next if $line =~ /TCP \(RST\)/;
    if ($line =~ /^(.*?) corerouter.* proto (\w+)[\s,].*?((?:(?:\d+\.){3}\d+|\[[0-9a-f:]+\])\:\d+)-\>((?:(?:\d+\.){3}\d+|\[[0-9a-f:]+\])\:\d+)/i) {
        my $date   = $1;
	my $proto  = $2;
        my $source = $3;
        my $dest   = $4;
	# The log format groups IP and port (ip:port)
	# so we have to extract each
        my ($srcip, $srcport) = $source =~ /(.*):(\d+)$/;
        my ($dstip, $dstport) = $dest   =~ /(.*):(\d+)$/;
        my $version = "IPv4"; # assume the worst
        if ($srcip =~ /^\[.+\]$/) {
            $srcip =~ s/^\[(.+)\]$/$1/;
            $version = "IPv6";
        }
        if ($dstip =~ /^\[.+\]$/) {
            $dstip =~ s/^\[(.+)\]$/$1/;
            $version = "IPv6";
        }
        next if $inside_network->($srcip);

	my $parsedate = str2time ($date, $timezone) or print "Weird date: $date\n";
	$parsedate += $timezone_secs;
        next unless $parsedate >= $startofday;
        next if $dstport == 0;

	# imagemap here
        my $y = int ($y2 - ($yfactor * (log($dstport)/log(10))));
        my $xdate = $date;
	# Convert the timestamp from the logs to a format
	# that can be used in the image map
        $xdate =~ s/^\w+\s+\d+\s(\d+)\:(\d+)+\:\d+/$1+($2\/60)/e;
        my $x = int ($x1 + ($xfactor * $xdate));
	$imagemap{$x}{$y}{$srcip} = "$proto/$dstport";

        push (@tcp4_pairs, [$parsedate, $dstport]) if ($proto eq "TCP" && $version eq "IPv4");
        push (@udp4_pairs, [$parsedate, $dstport]) if ($proto eq "UDP" && $version eq "IPv4");
        push (@tcp6_pairs, [$parsedate, $dstport]) if ($proto eq "TCP" && $version eq "IPv6");
        push (@udp6_pairs, [$parsedate, $dstport]) if ($proto eq "UDP" && $version eq "IPv6");
    }
}
close INPUT;

open (IMAGEMAP, ">", "${fireplot_basedir}/imagemap-${today}.map");
foreach my $xcoord (keys %imagemap) {
    foreach my $ycoord (keys %{$imagemap{$xcoord}}) {
        # print "X: $xcoord  Y: $ycoord\n";

        my @hits = ();
        while (my ($ipaddr, $port) = each %{$imagemap{$xcoord}{$ycoord}}) {
            push (@hits, "$ipaddr -> $port");
        }
        print IMAGEMAP "      <area alt=\"", join ('; ', @hits), "\" title=\"", join ('; ', @hits), "\" href=\"#\" shape=\"circle\" coords=\"${xcoord},${ycoord},2\" style=\"outline:none;\" target=\"_self\" />\n";
    }
}
close IMAGEMAP;

# Plot in dots
my $tcp4_dot = Chart::Gnuplot::DataSet->new(
    points  => \@tcp4_pairs,
    style   => "points",
    pointtype => 'dot-circle',
    pointsize => 0.1,
    timefmt => '%s',
    color   => $tcp4col,
);
my $udp4_dot = Chart::Gnuplot::DataSet->new(
    points  => \@udp4_pairs,
    style   => "points",
    pointtype => 'dot-circle',
    pointsize => 0.1,
    timefmt => '%s',
    color   => $udp4col,
);
my $tcp6_dot = Chart::Gnuplot::DataSet->new(
    points  => \@tcp6_pairs,
    style   => "points",
    pointtype => 'dot-circle',
    pointsize => 0.1,
    timefmt => '%s',
    color   => $tcp6col,
);
my $udp6_dot = Chart::Gnuplot::DataSet->new(
    points  => \@udp6_pairs,
    style   => "points",
    pointtype => 'fill-circle',
    pointsize => 0.1,
    timefmt => '%s',
    color   => $udp6col,
);

# Logarithmic scaling can be switched on or off
$chart->set (logscale => 'y');

my @datasets;
push @datasets, $tcp4_dot if @tcp4_pairs;
push @datasets, $udp4_dot if @udp4_pairs;
push @datasets, $tcp6_dot if @tcp6_pairs;
push @datasets, $udp6_dot if @udp6_pairs;

# Plot the graph
$chart->plot2d (@datasets);


