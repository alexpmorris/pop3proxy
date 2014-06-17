pop3proxy
=========

updated pop3proxy perl script to work with SpamAssassin 3.4.0

updated to work with SpamAssassin 3.4.0 and spamc on ubuntu (should work with other flavors as well)<br/>
for SSL, use stunnel4<br/>
  ie.  use /etc/spamassassin/hostmap.txt to map a port to stunnel4 (ie.  115 = 127.0.0.1:120)<br/>
       in /etc/stunnel/stunnel.conf:<br/>
      	[pop3s]<br/>
        accept = 127.0.0.1:120<br/>
        connect = pop.aol.com:995<br/>
        delay = yes<br/>
<br/>
requires perl module IPC::Run3<br/>
