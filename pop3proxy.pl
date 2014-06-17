#!perl -w

# Pop3proxy - a SpamAssassin enabled POP3 proxy designed for Win32
# users.

#updated APM 6/17/2014 to work with SpamAssassin 3.4.0 and spamc on ubuntu
#for SSL, use stunnel4
#  ie.  use /etc/spamassassin/hostmap.txt to map a port to stunnel4 (ie.  115 = 127.0.0.1:120)
#       in /etc/stunnel/stunnel.conf:
#	[pop3s]
#	accept = 127.0.0.1:120
#	connect = pop.aol.com:995
#	delay = yes

use strict;

# Set this to zero to turn off all debugging statements.  Set to 1 for
# basic debugging, which is pretty verbose, set it to 2 to add a dump
# of key data structs on connect, set it to 3 to add a dump of every
# read/write we do. (Oy)
use constant DEBUGGING => 1;

# Seems that SpamAssassin wants to remove the dependency on
# Time::HiRes.  I only need it for measuring performance, so I'll only
# include it if it's available.  Have to eval the "use constant"
# statements to avoid redefinition warnings.
#
# I use constants for debugging switches because I believe they get
# optimized out by the compiler if they're false.  I could be wrong.
BEGIN {
  eval "use Time::HiRes";
  if ($@) {
    eval "use constant TIMERS => 0";
  } else {
    eval "use constant TIMERS => 1";
  }
}

# A set of enumerated reasons why we're snarfing a multiline response
# for a socket.
use constant RETR => 1;
use constant TOP => 2;
use constant CAPA => 3;

use IO::Socket;
use IO::Select;

use IPC::Run3;

use FindBin;

use Getopt::Long;

#########################
# A BUNCH OF EVIL GLOBALS
#########################

# Set this to be a file that will contain the debug log.  Set to an
# empty string to debug to STDOUT.  --logfile command line arg sets.
my $logfile = 'pop3proxy.log';

# Hostmap - keys are ports to listen to on localhost, values are
# hostname:port to proxy connections on the key port to.  Set up by
# the command line --host arg or by the hostmap.txt config file.
#
# A simplest case - you get your mail from a server server named
# pophost.isp.com, on the standard POP3 port (110):
#
# my %hostmap = ( 110 => 'pophost.isp.com:110' );
#
# ...And you change your mail client to get mail from localhost.
#
# Fancier case - you pop mail off of two hosts, pophost.isp.com and
# mail.yetanother.org:
#
# my %hostmap = (
#    817 => 'pophost.isp.com:110',
#    818 => 'mail.yetanother.org:110',
# )
#
# In that case, the proxy listens to TWO sockets on localhost - 817,
# and 818, proxying off to two separate remote hosts as indicated.
#
# Note that for this to work, you need to be able to tell your mail
# client to connect to two different ports on localhost to find the
# proxy - namely, 817 for pophost.isp.com and 818 for
# mail.yetanother.org.  Some mail clients, like Netscape 4.5's, won't
# let you specify the port to use for a pop3 connection.  Oops.
# Others, like Mozilla 1.0, will let you set the port, but won't allow
# two servers to be on the same host (localhost in this case).  You
# can work around THAT by creating another alias for localhost in your
# C:\Windows\Hosts file:
#
# 127.0.0.1       localhost MyHostName
#
# ...and then configuring one account for localhost:817 and the other
# for MyHostName:818
my %hostmap = ();

# Respect_byte_count - If TRUE, then we do not alter the byte count of
# the message when marking it as spam - instead, we overwrite portions
# of the headers, such as changing the first five characters of the
# Subject: line to "*SPAM*" (a shortened form of SpamAssassin's famous
# subject prefix).  Set by the command line --nopad arguement.
#
# This, because under certain conditions the POP3 protocol indicates
# message and mailbox sizes, and the safe thing is not to enlarge
# those sizes while marking a message as spam.
#
# If there is no Subject: line in the mail headers (there doesn't have
# to be, after all) or if it's less than 5 bytes, then we use the
# first Received: line we find instead.

#
# Setting this value to FALSE (0) seems to work with most mail
# clients, and it causes us to proxy back the mail as it's been
# modified by SpamAssassin, which gives you a wonderful great lot of
# info about WHY it's labeled as spam, and also labels it clearly and
# beyond doubt, and defangs the MIME contents, etc, etc - but it
# *could* break the mail client.  Harumph.
my $respect_byte_count = 0;

# If true, we let the POP3 "TOP" command go thru to the server,
# otherwise, we don't proxy the TOP command and return an error back
# to the client.  Set by the command line --allowtop arguement.
#
# TOP is specified as an optional command, it shows you the headers of
# a mail message and a configurable number of lines of the body.  The
# idea is that you can sort of "screen" what you choose to download or
# not before you do.  All well and good, but our spam filtering can
# cause this to break when we scan the actual message during retrieval
# and potentially modify or add to the headers, such as changing the
# subject line to start with *****SPAM***** or something.
#
# This breaks the protocol a little and could have unusual or possibly
# even destructive consequences.  Since it's an optional part of the
# protocol, most mail clients should be coded to work without it,
# hence, by default, we avoid the problem by turning it off.
my $allow_top = 0;

# Here's the problem with using SpamAssassin in this way - given a
# large enough message, he will take a LONG time to scan it, where
# long is like sixteen minutes on a P-II 350 running Linux for a 3MB
# text message.  Maybe that was a degenerate case of some sort, but
# there it is.  If SpamAssassin takes long enough to scan a message,
# the mail client (who's not getting any data in response to his RETR
# command during all this) will eventually time out.  Sockets close,
# data is lost, etc, etc.  Very bad, very difficult to fix and get on
# with your life if you have a large mail message on the server that
# keeps causing this.
#
# Hence, this config parameter.  If a message exceeds this size while
# we're snarfing it, we'll abandon the snarf, start passing the data
# back to the client, and no scan of the message by SpamAssassin will
# be performed.
#
# Setting this to zero turns this behavior off - all messages will be
# scanned, regardless of size.
#
# I chose a 250K default for this value after analyzing a few months
# worth of spam - 1500 messages.  The average size was about 9K, the
# largest was 110K.  I figured double the largest would allow most of
# the spam we see today to get scanned, without trouble.
#
# This has the added side effect of keeping our memory usage down -
# that scan of a 3MB message took 86MB worth of memory.  That's not
# such a hot idea for a daemon.
my $max_scan_size = 250000;

# If we're invoked with a logfile for output using ActiveState's
# wperl.exe, we can effectively hum along in the background.  Nice.  I
# don't want to send the user to Task Manager to shut us down, and
# under Win98 at least you get the nasty "application not responding"
# dialog box because I'm busy waiting for to select a socket, so
# instead we have this - a port that we listen on for the purposes of
# exiting.  Any connection to it from localhost, and I'll get out of
# town.
#
# The default is 9625 (which is otherwise unused).  Set this to zero
# to disable this behavior.
my $exit_port = 9625;

# Note CRLF == \015\012
my $no_top = "-ERR Not supported by proxy\015\012";

# %peer - mapping of client socket => server socket, and vice versa.
#
# Keys are stringified references to IO::Socket objects, values are
# actual references to the same.  It's a little ugly to contemplate,
# but it works just dandy.
#
# The Peer mapping is removed when the peer is closed.  Thus, if
# you're reading data on $socket:
#
# The destination of this data is $reading_buf{$peer{$socket}}, and,
# If there is no destination any more, there's no point in reading the
# data, so shut down, and,
# If you read some data, add the $peer{$socket} to the Writeable set,
# because now you want to write something to him.
#
# And, if you're writing to $socket,
#
# The data is in $writing_buf{$socket}, and,
# Once all the data is written, you should close $socket if
# $peer{$socket} is missing.
my %peer;

# %is_client - stringified IO::Socket references for keys, true or
# false values based on whether that socket is connected to a client
# or the server.
my %is_client;

#################
# Buffers galore.
#################

# The general flow of data is:
#
# data from $socket -> $peer = $peer{$socket} -> read data into
# $reading_buf{$peer} -> hook protocol, snarfing to $message{$peer} if
# needed -> move data into $writing_buf{$peer} -> write data to $peer

# %reading_buf - keys are sockets, value is buffer of data read from that
# socket's peer, waiting to be proxy'd to the socket.
my %reading_buf;

# %writing_buf - keys are still sockets, value is data from the
# %reading_buf buffer which is now ready for writing to the socket.
my %writing_buf;

# Hash of socket => buffer, buffer is filled up with the message being
# snarfed.  Then the buffer is scanned and modified, then copied into
# $writing_buf{$socket} and flushed back to the client.
my %message;

# Hash of socket => enums, set to the reason we're snarfing a
# multiline response into %message_for array for this socket.  Set to
# zero (false) if we're NOT snarfing this data.
my %snarfing;

# Hash of Client socket => queue of commands the client has requested.
my %client_commands;

# Hash of listening sockets - keys are stringified socket object refs,
# values are the host:port we should proxy connections on that socket
# to.
my %proxyto;

# Flags - toggled on and off to indicate if we're reading a multiline
# response or not.  Keys are sockets.
my %reading_multiline_response;

# Hash - keys are sockets, values are HiRes timer floats.  Used to
# time downloads.
my %snarf_start;

########
# "Main"
########

# Get in your directory
chdir "$FindBin::RealBin";

read_config() if -s "./hostmap.txt";

my $cl_proxyto;
my $helpflag = 0;
usage() unless GetOptions("logfile:s" => \$logfile,
                          "nopad" => \$respect_byte_count,
                          "allowtop" => \$allow_top,
                          "maxscan=i" => \$max_scan_size,
                          "exitport=i" => \$exit_port,
                          "host=s" => \$cl_proxyto,
                          "help" => \$helpflag,
                          );

usage() if $helpflag;

if ($cl_proxyto) {
  warn "WARNING: $cl_proxyto overrides hostmap.txt entry: $hostmap{110}\n"
      if exists $hostmap{110};

  # We're nice to command line users.  If you tag a :port onto your
  # hostname, that's cool, otherwise, you get :110 for free.
  $cl_proxyto .= ':110' unless $cl_proxyto =~ /:\d+$/;
  $hostmap{110} = $cl_proxyto;
}

die "No proxy host!  Use --host or hostmap.txt\n" unless keys %hostmap;

# Prevent concurrent proxies - kill any previous instance
if (IO::Socket::INET->new(PeerAddr => 'localhost',
                          PeerPort => $exit_port,
                          Proto    => "tcp",
                          Type     => SOCK_STREAM)) {
  warn "WARNING: Existing proxy killed\n";
}

if ($logfile) {
  # Redirect stdout and stderr to logfile if specified.

  # Windows strangeness - you can't reopen STDOUT/STDERR successfully
  # under wperl.exe unless you've already closed it.  Go figure.
  close STDOUT;
  close STDERR;

  open(STDOUT, "> $logfile") or die "Can't redirect stdout: $!";
  open(STDERR, ">&STDOUT")   or die "Can't dup stdout: $!";
}

$| = 1;

my $readable = IO::Select->new;
my $writeable = IO::Select->new;

# Create sockets to listen on.
foreach my $port (keys %hostmap) {
  my $listener = IO::Socket::INET->new(LocalPort => $port, Listen => 5,
                                       Reuse => 1);

  die "Can't create socket for listening: $!" unless $listener;
  print "Listening for connections on port $port (proxy $hostmap{$port})\n"
      if DEBUGGING;

  $readable->add($listener);
  $proxyto{$listener} = $hostmap{$port};
}

# Create the "exit socket" - any connection on this socket from
# localhost will cause us to exit.
my $exit_socket;
if ($exit_port) {
  $exit_socket = IO::Socket::INET->new(LocalPort => $exit_port, Listen => 1,
                                       Reuse => 1);
  $readable->add($exit_socket);
}


while(1) {

  my ($toread, $towrite) = IO::Select->select($readable, $writeable);

  foreach my $socket (@$toread) {

    if ($socket == $exit_socket) {
      all_done($socket);
      next; # Just in case it wasn't from localhost
    }

    # Is it a new connection?
    if (exists $proxyto{$socket}) {

      dump_data_structs() if (DEBUGGING > 1);
      
      # Open connection to remote, add to readable set, map it
      # to this new client connection.
      my $remote = IO::Socket::INET->new(PeerAddr=>$proxyto{$socket});
      $readable->add($remote) if $remote;

      if (not $remote) {
        # Break the incoming new client off, create a new
        # listener to try again.
        print "Connect to remote: $proxyto{$socket} FAILED: $@\n" if DEBUGGING;
        my $port = $socket->sockport;
        $socket->close;
        $readable->remove($socket);
        my $listener = IO::Socket::INET->new(LocalPort => $port,
                                             Listen => 5, Reuse => 1);
        die "Can't create socket for listening: $!" unless $listener;
        $readable->add($listener);
        $proxyto{$listener} = $hostmap{$port};
        next;
      }

      # Accept the connection and add it to our readable list.
      my $new_sock = $socket->accept;
      $readable->add($new_sock) if $new_sock;
      die "Can't create new socket for incoming connection: $!"
          unless $new_sock;

      # Create proxy/peer mapping, set client/server indicators,
      # create buffers, etc.
      $peer{$new_sock} = $remote;
      $peer{$remote} = $new_sock;
      $is_client{$new_sock} = 1;
      $is_client{$remote} = 0;
      $message{$new_sock} = '';
      $snarfing{$new_sock} = 0;

      # The first thing we'll see is a response to no command at
      # all - "+OK Welcome to foobar.com" - so we seed the
      # command queue with a dummy command to eleminate warnings
      # later on.
      $client_commands{$new_sock} = [('none')];
      foreach ($new_sock, $remote) {
        $reading_buf{$_} = '';
        $writing_buf{$_} = '';
      }

      if (DEBUGGING) {
        print "\nNew connection:\n";
        print "From: ", $new_sock->peerhost, ':',
        $new_sock->peerport,"\n";
        print "To:   ", $remote->peerhost, ':',
        $remote->peerport, "\n";
      }

    } else {  # It's an established connection

      my $key;
      if (DEBUGGING) {
        if ($socket->connected) {
          $key = $socket->peerhost . ':' . $socket->peerport;
        } else {
          $key = "$socket";
        }
      }
      my $proxy; # Which socket we're going to proxy this data to
      if (exists $peer{$socket}) {
        $proxy = $peer{$socket};
      } else {
        # No peer.
        print "\n$key - peer gone on read" if DEBUGGING;

        # No need to keep hearing about how it's ready to be
        # read - we've got no use for subsequent data.
        $readable->remove($socket);

        # Tear down connection, unless there's data waiting to
        # be written to it - in that case, we'll catch it in
        # writeables and close it when we're done.
        if (! data_waiting($socket)) {
          print ", nothing to write, closing socket" if DEBUGGING;
          clean_up($socket);
        }
        print "\n" if DEBUGGING;
        next;
      }

      # Why 4096 bytes?  I dunno.  You got a better buffer size?
      unless (my $n = sysread($socket, $reading_buf{$proxy}, 4096,
                              length($reading_buf{$proxy}))) {
        warn "sysread: $!\n" if not defined $n;
        # Shut down the socket
        print "\n$key - socket close on read" if DEBUGGING;
        clean_up($socket);
        # Remove the proxy map
        delete $peer{$socket};
        delete $peer{$proxy};
        if (! data_waiting($proxy)) {
          # No pending data - tear down the peer as well.
          print ", closing peer too" if DEBUGGING;
          clean_up($proxy);
        }
        print "\n" if DEBUGGING;
        next;
      }
      
      if (DEBUGGING > 2) {
        $is_client{$socket} ? print "C< " : print "S< ";
        print "\n";
      }

      # Got data from a socket.  Go do something clever with it.
      run_hooks($proxy);
    }           

  } # End of readables

  # Next, do something with each socket ready to write.  Like, write
  # to it.
  foreach my $socket (@$towrite) {

    my $key;
    if (DEBUGGING) {
      if ($socket->connected) {
        $key = $socket->peerhost . ':' . $socket->peerport;
      } else {
        $key = "$socket";
      }
    }

    my $wrote = syswrite($socket, $writing_buf{$socket}) or do {
      warn "syswrite: $!\n";
      print "\n$key - socket close on write" if DEBUGGING;
      clean_up($socket);
      # Remove the proxy map
      if (exists $peer{$socket}) {
        my $proxy = $peer{$socket};
        delete $peer{$proxy};
        delete $peer{$socket};
        
        if (! data_waiting($proxy)) {
          print ", closing peer too" if DEBUGGING;
          clean_up($proxy);
        }
      }

      print "\n" if DEBUGGING;
      next;
    };

    if (DEBUGGING > 2) {
      $is_client{$socket} ? print "C> " : print "S> ";
      print "\n";
    }
    
    # Scrub the just-written data from the buffer
    substr($writing_buf{$socket}, 0, $wrote, "");

    # All done writing?
    if (! length($writing_buf{$socket})) {
      $writeable->remove($socket);

      if (! exists $peer{$socket}) {
        # No peer?  Tear down connection.
        print "\n$key - peer gone after write, closing\n" if DEBUGGING;
        clean_up($socket);
        next;
      }
    }
  } # end of writeables
}


# data_waiting($socket)
#
# Returns true if there's any data waiting to be proxy'd to this socket.
#
# Reason this works - we only check data_waiting() on a socket *after*
# we've closed it's peer.  Closing the peer in clean_up(), below, will
# have the effect of flushing any pending %message buffers (and
# %reading_buf, for that matter) to %writing_buf, and hence, all the
# data which is "waiting" is, in fact, guaranteed to now be waiting.
sub data_waiting {
  my $socket = shift;
  return (length($reading_buf{$socket}) or length($writing_buf{$socket}));
}


# clean_up($socket)
#
# Given a socket, close it, stop selecting it for anything, clean up
# all our structs that refer to it, set the peer if any to flush
# buffers.
sub clean_up {
  my $socket = shift;

  # This socket is history.  If there's a peer, then that peer
  # currently has all the data it's ever gonna get.  Flush that data
  # into the writing_buf and add it to the writeable set.
  #
  # Ok, technically, this *could* burn you if what you were caching
  # away in %message was a multiline TOP response that you were
  # going to discard anyway, and now I'm going to flush it to the
  # client, instead.  Look, the client is going to get an error
  # condition *anyway* because the darn socket is GONE, man, just
  # like that, in the middle of a multiline response!  I will
  # venture to say that no harm will come of this - but if it does,
  # we can always make this behave a lot more like a "last ditch"
  # run_hooks() session.
  if (exists $peer{$socket}) {
    my $proxy = $peer{$socket};
    $writing_buf{$proxy} .= $message{$proxy} if exists ($message{$proxy});
    $writing_buf{$proxy} .= $reading_buf{$proxy};
    $reading_buf{$proxy} = '';
    $message{$proxy} = '';
    $snarfing{$proxy} = 0;
    if (length ($writing_buf{$proxy})) {
      $writeable->add($proxy);
      print "\nFlushing peer on close\n" if DEBUGGING;
    }
  }

  # Note that you can apparently remove a socket more than once from
  # an IO::Select set.  Also you can delete a key/value pair from a
  # hash that doesn't exist.  Love Perl.  DWIM.
  $readable->remove($socket);
  $writeable->remove($socket);
  $socket->close;
  delete $reading_buf{$socket};
  delete $writing_buf{$socket};
  delete $is_client{$socket};
  delete $snarfing{$socket};
  delete $message{$socket};
  delete $client_commands{$socket};
  delete $reading_multiline_response{$socket};
  delete $snarf_start{$socket};
}


# run_hooks($socket)
#
# This is where we hook the POP3 protocol.  Called whenever a socket
# gets new data in it's buffer, we can do whatever you want here.  The
# default is to wait until there's a \n in the %reading_buf buffer, then (in
# a loop) move all those bytes into the %writing_buf buffer (giving us the
# window to look at a full line of I/O), then add the socket to the
# writeable set, thereby causing the contents of %writing_buf to get
# flushed to the socket.
#
# Under certain conditions, though, we'll want to intercept the
# protocol, at which point we snarf the data off into %message until
# it's done, then we look at it or replace it or something, and THEN
# we ship it off to %writing_buf for flushing to the client.
#
# Client commands are pushed onto a queue of commands, server
# responses shift commands off that queue.  This way we can support
# pipelining client/servers, per rfc 2449
#
# Note - logically, the %peer mapping must be intact when you get
# here.  The main loop enforces this.  You may assume that
# $peer{$socket} will exist and be valid in this routine.
my $pos;
sub run_hooks {
  my $socket = shift;

  # This loop looks for the first occurance of a \n in a string,
  # then MOVES all of the string up to and including the \n into the
  # output buffer and adds the socket to the set of sockets we'd
  # like to write to.  Then it loops looking for another \n.
  #
  # Just before the move, you can examine the beginning of
  # $reading_buf{$socket} to see what kinds of interesting thingies might
  # be in there, in the confidence that it's a real full line of
  # data from the protocol.  You can say things like:
  #
  # $reading_buf{$socket} =~ /^(.*)$/m  # /m lets $ match next to embedded \n
  $pos = -1;
  while (($pos = index($reading_buf{$socket}, "\012", 0)) > -1) {
    # Right here you can examine $reading_buf{$socket}
    if ($is_client{$socket}) {
      # Hooks here for data from the server to the client

      # Responses from the server are interesting.  They can be
      # single line, in which case they MUST start with "+OK" or
      # "-ERR", or else they're part of a multiline response,
      # such as a LIST or RETR command, in which case they MUST
      # end with a CRLF.CRLF.

      if ($reading_buf{$socket} =~ /^(\+OK|-ERR)/i 
          and not $reading_multiline_response{$socket}) {

        # Response to a command
        my $command = shift @{$client_commands{$socket}};

        print $peer{$socket}->peerhost . ':' .
            $peer{$socket}->peerport .
            " (Server) said $1 to $command\n" if DEBUGGING;
        
        # Always include the greeting line in the log. 
        if (DEBUGGING and $command eq 'none') {
          print $reading_buf{$socket};
        }

        die "Assertion failed: snarfing outside multiline response" 
            if ($snarfing{$socket});

        # Only interested in snarfing successful response -
        # none of the error responses are multiline.
        if (substr ($1, 0, 1) eq '+') {
          if ($command =~ /^TOP$/i and not $allow_top) {
            print "Snarfing TOP response\n" if DEBUGGING;
            $snarfing{$socket} = TOP;
          }
          
          if ($command =~ /RETR/i) {
            print "Snarfing RETR response\n" if DEBUGGING;
            $snarf_start{$socket} = Time::HiRes::gettimeofday
                if TIMERS;
            $snarfing{$socket} = RETR;
          }

          if ($command =~ /CAPA/i) {
            print "Snarfing CAPA response\n" if DEBUGGING;
            $snarfing{$socket} = CAPA;
          }
        }
        
      } elsif ($reading_buf{$socket} =~ m|^\.\015?\012|) {
        # End of a multiline response

        $reading_multiline_response{$socket} = 0;

        if ($snarfing{$socket}) {
          print "Detected end of snarfed multiline\n" if DEBUGGING;

          printf "Download took %.8f seconds\n",
          Time::HiRes::gettimeofday - $snarf_start{$socket}
          if (DEBUGGING and TIMERS);

          # At this point, $message{$socket} contains the
          # full multiline response, +OK up to but not
          # including this trailing ".CRLF".

          if ($snarfing{$socket} == RETR) {

            # Right here, $message{$socket} is ripe for
            # scanning.
            scan_mail(\$message{$socket});
            $writing_buf{$socket} .= $message{$socket};

          } elsif ($snarfing{$socket} == TOP) {
            # Eat the .CRLF, add the error message to the
            # output buffer, flush said output buffer,
            # clean up your structs and move on.
            substr($reading_buf{$socket}, 0, $pos+1, "");
            $writing_buf{$socket} .= $no_top;
            $message{$socket} = '';
            $snarfing{$socket} = 0;
            $writeable->add($socket);
            next;
          } elsif ($snarfing{$socket} == CAPA) {
            # Strips out the TOP response, if any.
            $message{$socket} =~ s/\012TOP[^\012]*\012/\012/ig
                if not $allow_top;
            # Strips out the SASL response, if any.
            $message{$socket} =~ s/\012SASL[^\012]*\012/\012/ig;
            $writing_buf{$socket} .= $message{$socket};
          }
          $message{$socket} = '';
          $snarfing{$socket} = 0;
        }
      } else {
        # Part of a multiline response.  Flip the ready flag,
        # you won't be ready to see another response until you
        # see your CRLF.CRLF
        $reading_multiline_response{$socket} = 1;
      }

      # At this point, snarf data into %message if snarfing and
      # move along.
      if ($snarfing{$socket}) {
        $message{$socket} .=
            substr($reading_buf{$socket}, 0, $pos+1, "");

        # Check size of snarfed message and stop snarfing if it's
        # getting too big - see notes at $max_scan_size.
        if ($max_scan_size != 0 and 
            length($message{$socket}) > $max_scan_size) {

          print "Message exceeding max scan size, abandoning snarf\n"
              if DEBUGGING;

          $writing_buf{$socket} .= $message{$socket};

          $message{$socket} = '';
          $snarfing{$socket} = 0;
          $writeable->add($socket);
        }

        next;
      }

    } else {
      # Hooks here for data from the client to the server

      # Spot the client's command, add to the queue.
      my ($command) = $reading_buf{$socket} =~ /^(\S+)\s/;

      print $peer{$socket}->peerhost . ':' . $peer{$socket}->peerport .
          " (Client) said $command\n" if DEBUGGING and $command;

      # AUTH is a special case, see discussion elsewhere.  Must
      # not have any commands in the queue, and we reply back to
      # the socket immediately with an error.
      if ($command and $command =~ /^AUTH$/i) {
        if (scalar(@{$client_commands{$peer{$socket}}})) {
          die "I so can't cope with AUTH commands while pipelining";
        }

        print "AUTH Rejected\n" if DEBUGGING;
        substr($reading_buf{$socket}, 0, $pos+1, "");
        # Note - $no_top is a generic -ERR response, works fine.
        $writing_buf{$peer{$socket}} .= $no_top;
        $writeable->add($peer{$socket});
        next;
      }

      push (@{$client_commands{$peer{$socket}}}, $command) if $command;
    }

    # Default action after all your shots at hooking and magic,
    # etc.: Move the data to the writing buffer, and set it up to
    # get written.

    $writing_buf{$socket} .= substr($reading_buf{$socket}, 0, $pos+1, "");
    $writeable->add($socket);
  }
}

sub dump_data_structs {
  # Dump your current key per-connection data structs
  print "\nExisting proxy/peer mappings:\n";
  print map "$_ => $peer{$_}\n", keys %peer;
  print "\nExisting is_client flags:\n";
  print map "$_ => $is_client{$_}\n", keys %is_client;
  print "Existing socket reading_buf buffers:\n";
  print map "$_ => $reading_buf{$_}\n", keys %reading_buf;
  print "Existing socket writing_buf buffers:\n";
  print map "$_ => $writing_buf{$_}\n", keys %writing_buf;
  print "Existing message buffers:\n";
  print map "$_ => $message{$_}\n", keys %message;
  print "Existing snarfing flags:\n";
  print map "$_ => $snarfing{$_}\n", keys %snarfing;
  print "Existing command queues:\n";
  print map "$_ => @{$client_commands{$_}}\n", keys %client_commands;
  print "Existing reading_multiline_response flags:\n";
  print map "$_ => $reading_multiline_response{$_}\n", 
  keys %reading_multiline_response;
  print "Existing snarf_start values:\n";
  print map "$_ => $snarf_start{$_}\n", keys %snarf_start;
}

# @mail - array of lines of a mail message.  Some notes on memory
# usage here:
#
# Big mail messages getting copied about will chew up memory right
# quick.  I start with one copy of the message built up in a scalar
# buffer, then I need a second copy, broken out into an array of
# lines, for Mail::SpamAssassin::NoMailAudit to chew on.  That's two
# copies.
#
# I can save a copy's worth of memory by MOVING the lines from the
# scalar buffer into the array - but then, once SpamAssassin is done
# chewing on them, I have to put them BACK into the scalar buffer.  If
# I'm not removing them from the SpamAssassin::NoMailAudit object as I
# do that, I'm going to wind up with a second copy of the mail
# *anyway*.  And that kind of removal is nasty and creeps inside of
# the objects encapsulation, where I really ought not go.
#
# NoMailAudit::as_string() returns a copy of the mail as a string, but
# to do so, it creates a big ol' scalar on the stack to return.
# Simple, but it costs a THIRD chunk of memory the size of the
# message.
my @mail;

sub scan_mail {
  my $mailref = shift;

  my $bytecount = length $$mailref;

  $$mailref =~ s/\012\.\./\012\./g; # un-byte-stuff

  @mail = split /^/, $$mailref;

  my $response = shift @mail;

  my $message = "";
  foreach my $line (@mail) {
    $message .= $line;
  }

  my $start;
  $start = Time::HiRes::gettimeofday if TIMERS;
  my ($cmd_out, $cmd_err);
  run3(['spamc','-c','-F','/etc/spamassassin/local.cf'], \$message, \$cmd_out, \$cmd_err);
  printf "Spam check took %.2f seconds, ", Time::HiRes::gettimeofday - $start if (DEBUGGING and TIMERS);
  printf "bytesIn: %d, bytesOut: %d\n", length($message), length($cmd_out);

  $$mailref = "\n".$cmd_out;
  $$mailref =~ s/\012\./\012\.\./g; # byte-stuff
}


sub all_done {
  my $socket = shift;
  my $new_sock = $socket->accept;
  if ($new_sock->peerhost eq '127.0.0.1') {
    print "Connection on exit socket, exiting\n" if DEBUGGING;
    exit;
  } else {
    print "Connection on exit socket from non-local host!\n" if DEBUGGING;
    $new_sock->close;
  }
}


sub read_config {
  open (CONFIG, "./hostmap.txt") or die "Can't read hostmap.txt: $!\n";
  # Straight from the cookbook 8.16
  while (<CONFIG>) {
    chomp;                  # no newline
    s/#.*//;                # no comments
    s/^\s+//;               # no leading white
    s/\s+$//;               # no trailing white
    next unless length;     # anything left?
    my ($port, $proxyto) = split(/\s*=\s*/, $_, 2);
    $hostmap{$port} = $proxyto;
  }
}


sub usage {
  print <<EOT;
Usage: $0 --host some.host.name [options]
Options include:
  --logfile filename
      Use filename as the log file.  Default is pop3proxy.log.  If the
      filename is omitted, log to STDOUT.
  --nopad
      If nopad is specified, then message sizes will not be changed as a
      result of spam scanning.  The default is to add to the message size.
  --allowtop
      If top is specified, then the POP3 "TOP" command will be passed through
      to the server.  The default is to reject client TOP commands with an
      error message.
  --maxscan bytes
      Messages which exceed this size will not be scanned for spam.  The
      default is 250000.  Setting this to zero disables this behavior.
  --exitport port
      Any connection from localhost on this port will cause us to exit.
      The default is 9625.  Setting this to zero disables this behavior.
EOT
  exit;
}

#            Copyright (c) 2002, Dan McDonald. All Rights Reserved.
#        This program is free software. It may be used, redistributed
#        and/or modified under the terms of the Perl Artistic License
#             (see http://www.perl.com/perl/misc/Artistic.html)
