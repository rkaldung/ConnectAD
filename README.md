ConnectAD
=========

This is an OTRS package for authentication (agents and users) and syncing (agents) against an Active Directory.
All configured groups can be nested to support [AGDLP](http://en.wikipedia.org/wiki/AGDLP)

## Kernel::System::Auth::ConnectAD ##



Tips & Tricks
-------------

* use multiple domain controllers with failover

````perl
    #select your domain controller
    my @DCs = ('dc1.domain.tld', 'dc2.domain.tld');

	#recommended with LDAPs 
    my @DCs = ('ldaps://dc1.domain.tld:636/', 'ldaps://dc2.domain.tld:636/');
 
    $Self->{'AuthModule::AD::Host'} = \@DCs;
    # specify the failover timeout in seconds
    $Self->{'Customer::AuthModule::AD::Params'}    = {
        timeout => 2,
    }; 
````