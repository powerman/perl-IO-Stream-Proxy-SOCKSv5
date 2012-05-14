package IO::Stream::Proxy::SOCKSv5;

use warnings;
use strict;
use Carp;

use version; our $VERSION = qv('1.0.1');    # update POD & Changes & README

# update DEPENDENCIES in POD & Makefile.PL & README
use IO::Stream::const;
use IO::Stream::EV;
use Scalar::Util qw( weaken );

use constant HANDSHAKE      => 1;
use constant CONNECTING     => 2;

                                    ### SOCKS protocol constants:
use constant VN             => 0x05;# version number (5)
use constant AUTH_NO        => 0x00;# authentication method id
use constant CD             => 0x01;# command code (CONNECT)
## no critic (Capitalization)
use constant ADDR_IPv4      => 0x01;# address type (IPv4)
use constant ADDR_DOMAIN    => 0x03;# address type (DOMAIN)
use constant ADDR_IPv6      => 0x04;# address type (IPv6)
use constant LEN_IPv4       => 4;
use constant LEN_IPv6       => 16;
## use critic
use constant REPLY_LEN_HANDSHAKE=> 2; # reply length for handshake (bytes)
use constant REPLY_LEN_CONNECT  => 4; # reply length for connect header (bytes)
use constant REPLY_CD       => 0x00;# reply code 'request granted'


sub new {
    my ($class, $opt) = @_;
    croak '{host}+{port} required'
        if !defined $opt->{host}
        || !defined $opt->{port}
        ;
    my $self = bless {
        host        => undef,
        port        => undef,
#        user        => q{},    # TODO
#        pass        => q{},    # TODO
        %{$opt},
        out_buf     => q{},                 # modified on: OUT
        out_pos     => undef,               # modified on: OUT
        out_bytes   => 0,                   # modified on: OUT
        in_buf      => q{},                 # modified on: IN
        in_bytes    => 0,                   # modified on: IN
        ip          => undef,               # modified on: RESOLVED
        is_eof      => undef,               # modified on: EOF
        _want_write => undef,
        _state      => 0,                   # HANDSHAKE -> [AUTH] -> CONNECTING
        _port       => undef,
        }, $class;
    return $self;
}

sub PREPARE {
    my ($self, $fh, $host, $port) = @_;
    croak '{fh} already connected'
        if !defined $host;
    $self->{_port} = $port;
    $self->{_slave}->PREPARE($fh, $self->{host}, $self->{port});
    IO::Stream::EV::resolve($host, $self, sub {
        my ($self, $ip) = @_;
        $self->{_master}{ip} = $ip;
        $self->{_state} = HANDSHAKE;
        my @auth = ( AUTH_NO );
        $self->{out_buf} = pack 'C C C*', VN, 0+@auth, @auth;
        $self->{_slave}->WRITE();
    });
    return;
}

sub WRITE {
    my ($self) = @_;
    $self->{_want_write} = 1;
    return;
}

sub EVENT { ## no critic (ProhibitExcessComplexity)
    ## no critic (ProhibitDeepNests)
    my ($self, $e, $err) = @_;
    my $m = $self->{_master};
    if ($err) {
        $m->EVENT(0, $err);
    }
    if ($e & IN) {
        if ($self->{_state} == HANDSHAKE) {
            if (length $self->{in_buf} < REPLY_LEN_HANDSHAKE) {
                $m->EVENT(0, 'socks v5 proxy: protocol error');
            } else {
                my ($vn, $auth) = unpack 'CC', $self->{in_buf};
                substr $self->{in_buf}, 0, REPLY_LEN_HANDSHAKE, q{};
                if ($vn != VN) {
                    $m->EVENT(0, 'socks v5 proxy: unknown version of reply code');
                }
                elsif ($auth != AUTH_NO) {
                    $m->EVENT(0, 'socks v5 proxy: auth method handshake error');
                }
                else {
                    $self->{_state} = CONNECTING;
                    $self->{out_buf} = pack 'C C C C CCCC n',
                        VN, CD, 0, ADDR_IPv4,
                        split(/[.]/xms, $self->{_master}{ip}), $self->{_port};
                    $self->{_slave}->WRITE();
                }
            }
        }
        elsif ($self->{_state} == CONNECTING) {
            if (length $self->{in_buf} < REPLY_LEN_CONNECT) {
                $m->EVENT(0, 'socks v5 proxy: protocol error');
            } else {
                my ($vn, $cd, $atype) = unpack 'CCxC', $self->{in_buf};
                substr $self->{in_buf}, 0, REPLY_LEN_CONNECT, q{};
                if ($vn != VN) {
                    $m->EVENT(0, 'socks v5 proxy: unknown version of reply code');
                }
                elsif ($cd != REPLY_CD) {
                    $m->EVENT(0, 'socks v5 proxy: error '.$cd);
                }
                elsif ($atype != ADDR_IPv4 && $atype != ADDR_DOMAIN && $atype != ADDR_IPv6) {
                    $m->EVENT(0, 'socks v5 proxy: unknown address type '.$atype);
                }
                else {
                    my $tail_len
                        = $atype == ADDR_IPv4   ? LEN_IPv4+2
                        : $atype == ADDR_DOMAIN ? 1+unpack('C', $self->{in_buf})+2
                        :                         LEN_IPv6+2
                        ;
                    if (length $self->{in_buf} < $tail_len) {
                        $m->EVENT(0, 'socks v5 proxy: protocol error');
                    } else {
                        substr $self->{in_buf}, 0, $tail_len, q{};
                        # SOCKS v5 protocol done
                        $e = CONNECTED;
                        if (my $l = length $self->{in_buf}) {
                            $e |= IN;
                            $m->{in_buf}    .= $self->{in_buf};
                            $m->{in_bytes}  += $l;
                        }
                        $m->EVENT($e);
                        $self->{_slave}->{_master} = $m;
                        weaken($self->{_slave}->{_master});
                        $m->{_slave} = $self->{_slave};
                        if ($self->{_want_write}) {
                            $self->{_slave}->WRITE();
                        }
                    }
                }
            }
        }
    }
    if ($e & EOF) {
        $m->{is_eof} = $self->{is_eof};
        $m->EVENT(0, 'socks v5 proxy: unexpected EOF');
    }
    return;
}


1; # Magic true value required at end of module
__END__

=head1 NAME

IO::Stream::Proxy::SOCKSv5 - SOCKSv5 proxy plugin for IO::Stream


=head1 VERSION

This document describes IO::Stream::Proxy::SOCKSv5 version 1.0.1


=head1 SYNOPSIS

    use IO::Stream;
    use IO::Stream::Proxy::SOCKSv5;

    IO::Stream->new({
        ...
        plugin => [
            ...
            proxy   => IO::Stream::Proxy::SOCKSv5->new({
                host    => 'my.proxy.com',
                port    => 3128,
            }),
            ...
        ],
    });


=head1 DESCRIPTION

This module is plugin for L<IO::Stream> which allow you to route stream
through SOCKSv5 proxy.

You may use several IO::Stream::Proxy::SOCKSv5 plugins for single IO::Stream
object, effectively creating proxy chain (first proxy plugin will define
last proxy in a chain).

=head2 SECURITY

While version 5 of SOCKS protocol support domain name resolving by proxy,
it unable to report resolved IP address, which is required by IO::Stream
architecture, so resolving happens always on client side. This may result
in leaking client's DNS resolver IP address (usually it's client's address
or client's ISP address) and detecting the fact of using proxy.

=head2 EVENTS

When using this plugin event RESOLVED will never be delivered to user because
there may be two hosts to resolve (target host and proxy host) and it
isn't clear how to handle this case in right way.

Event CONNECTED will be generated after SOCKS proxy successfully connects to
target {host} (and not when socket will connect to SOCKS proxy itself).


=head1 INTERFACE 

=over

=item new({ host=>$host, port=>$port })

Connect to proxy $host:$port.

=back


=head1 DIAGNOSTICS

=over

=item C<< {host}+{port} required >>

You must provide both {host} and {port} to IO::Stream::Proxy::SOCKSv5->new().

=item C<< {fh} already connected >>

You have provided {fh} to IO::Stream->new(), but this is not supported by
this plugin. Either don't use this plugin or provide {host}+{port} to
IO::Stream->new() instead.

=back



=head1 CONFIGURATION AND ENVIRONMENT

IO::Stream::Proxy::SOCKSv5 requires no configuration files or environment variables.


=head1 DEPENDENCIES

L<IO::Stream>.


=head1 INCOMPATIBILITIES

None reported.


=head1 BUGS AND LIMITATIONS

Only these authentication methods supported:

 - no authentication

SOCKS "BIND" request doesn't supported.

SOCKS "associate UDP" request doesn't supported.

No bugs have been reported.

Please report any bugs or feature requests to
C<bug-io-stream-proxy-socksv5@rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org>.


=head1 AUTHOR

Alex Efros  C<< <powerman-asdf@ya.ru> >>


=head1 LICENSE AND COPYRIGHT

Copyright (c) 2010, Alex Efros C<< <powerman-asdf@ya.ru> >>. All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.


=head1 DISCLAIMER OF WARRANTY

BECAUSE THIS SOFTWARE IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
FOR THE SOFTWARE, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN
OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
PROVIDE THE SOFTWARE "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOFTWARE IS WITH
YOU. SHOULD THE SOFTWARE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL
NECESSARY SERVICING, REPAIR, OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
REDISTRIBUTE THE SOFTWARE AS PERMITTED BY THE ABOVE LICENCE, BE
LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL,
OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE
THE SOFTWARE (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING
RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A
FAILURE OF THE SOFTWARE TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF
SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.
