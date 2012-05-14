use inc::Module::Install;

name     'IO-Stream-Proxy-SOCKSv5';
all_from 'lib/IO/Stream/Proxy/SOCKSv5.pm';
author   'Alex Efros <powerman-asdf@ya.ru>';
license  'perl';

requires	'version';
requires	'IO::Stream';

test_requires	'Test::More';
test_requires	'Test::Exception';
test_requires	'EV';

recommends      'Test::CheckManifest'   => '0.9';
recommends      'Test::Perl::Critic';
recommends      'Test::Pod::Coverage'   => '1.08';
recommends      'Pod::Coverage'         => '0.18';
recommends      'Test::Pod'             => '1.22';

my $online = prompt 'Run tests which require internet connection', 'n';
$online = lc $online eq 'y' ? 'y' : 'n';
my ($host, $port, $user, $pass);
if ($online eq 'y') {
    $host = prompt 'Please enter SOCKSv5 proxy host', q{};
    $port = prompt 'Please enter SOCKSv5 proxy port', '1080';
}
open my $f, '>', 't/config.pm' or die "open: $!";
printf {$f} "use constant CFG_ONLINE => '%s';\n", $online;
printf {$f} "use constant CFG_HOST   => '%s';\n", $host;
printf {$f} "use constant CFG_PORT   => '%s';\n", $port;
printf {$f} '1;';
close $f or die "close: $!";

auto_install;

WriteAll;
