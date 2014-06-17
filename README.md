pop3proxy
=========

updated pop3proxy perl script to work with SpamAssassin 3.4.0

updated to work with SpamAssassin 3.4.0 and spamc on ubuntu (should work with other flavors as well)
for SSL, use stunnel4
  ie.  use /etc/spamassassin/hostmap.txt to map a port to stunnel4 (ie.  115 = 127.0.0.1:120)
       in /etc/stunnel/stunnel.conf:
      	[pop3s]
        accept = 127.0.0.1:120
        connect = pop.aol.com:995
        delay = yes

requires perl module IPC::Run3
