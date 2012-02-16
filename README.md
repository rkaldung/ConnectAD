ConnectAD
=========

This is an OTRS package for authentication (agents and users) and syncing (agents) against an Active Directory.
All configured groups can be nested to support [AGDLP](http://en.wikipedia.org/wiki/AGDLP)

## Installation via SysConfig and Package Manager ##

For an easy installation (without command line) add my repository to your configuration.
Go to Admin -> SysConfig -> Framework -> Core::Package. Enable Package::RepositoryList and add the following entry:

	Key: http://otrs.kaldung.com/packages30
	Content: OTRS Repo kaldung.com
	
Now you are able to add ConnectAD to your OTRS. The configuration is done via editing Kernel/Config.pm, example are shown below.


## Kernel::System::Auth::ConnectAD ##

Here is an example configuration for authentication:

````perl
    # choose ConnectAD for agent authentication
    $Self->{'AuthModule'} = 'Kernel::System::Auth::ConnectAD';
    # which Domain Controller to use
    $Self->{'AuthModule::ConnectAD::Host'} = 'dc.example.org';
    # your AD's BaseDN
    $Self->{'AuthModule::ConnectAD::BaseDN'} = 'ou=User,dc=example,dc=org';
    # good values for AD are userPrincipalName, mail or sAMAccountName
    $Self->{'AuthModule::ConnectAD::UID'} = 'sAMAccountName';
    # use LOGIN for the same method like LDAP, SSO for NTLM/Keberos Single Sign On
    $Self->{'AuthModule::ConnectAD::AuthType'} = 'LOGIN';
    # agents have to be member of this group, nested groups are supported ;-)
    $Self->{'AuthModule::ConnectAD::GroupDN'} = 'CN=OTRS-agents,OU=Groups,DC=example,DC=org';
    $Self->{'AuthModule::ConnectAD::AccessAttr'} = 'member';
    $Self->{'AuthModule::ConnectAD::UserAttr'} = 'DN';
    #you need an AD user to read from AD
    # use the user's DN or his userPrincipalName
    $Self->{'AuthModule::ConnectAD::SearchUserDN'} = 'ldapuser@example.org';
    $Self->{'AuthModule::ConnectAD::SearchUserPw'} = 'secret';
    # ignore entries with objectClass=contact
    $Self->{'AuthModule::ConnectAD::AlwaysFilter'} = '(!(objectClass=contact))';
    
````
## Kernel::System::Auth::Sync::ConnectAD ##

````perl
    # Synchronisierung Agenten aus dem AD inkl. Rollen
    $Self->{'AuthSyncModule'} = 'Kernel::System::Auth::Sync::ConnectAD';
    $Self->{'AuthSyncModule::ConnectAD::Host'} = 'dc.example.org';
    $Self->{'AuthSyncModule::ConnectAD::BaseDN'} = 'DC=example,DC=org';
    $Self->{'AuthSyncModule::ConnectAD::UID'} = 'sAMAccountName';
    $Self->{'AuthSyncModule::ConnectAD::SearchUserDN'} = 'ldapuser@example.org';
    $Self->{'AuthSyncModule::ConnectAD::SearchUserPw'} = 'secret';
    $Self->{'AuthSyncModule::ConnectAD::AccessAttr'} = 'member';
    $Self->{'AuthSyncModule::ConnectAD::UserAttr'} = 'DN';
    $Self->{'AuthSyncModule::ConnectAD::AlwaysFilter'} = '(!(objectClass=contact))';

    # the minimum amount of data to sync
    $Self->{'AuthSyncModule::ConnectAD::UserSyncMap'} = {
        UserFirstname => 'givenName',
        UserLastname => 'sn',
        UserEmail => 'mail',
    };
    
    # sync group membership to OTRS roles
    $Self->{'AuthSyncModule::ConnectAD::UserSyncRolesDefinition'} = {
	    'CN=First Level,OU=Groups,DC=example,DC=org' => {
	        'FirstLevelAgents' => 1,
	    },
	    'CN=Second Level,OU=Groups,DC=example,DC=org' => {
	        'SecondLevelAgents' => 1,
	    },
	    ...
    };

    
````


Tips & Tricks
-------------

* use multiple domain controllers with failover

````perl
    #select your domain controller
    my @DCs = ('dc1.domain.tld', 'dc2.domain.tld');

	#recommended with LDAPs 
    my @DCs = ('ldaps://dc1.domain.tld:636/', 'ldaps://dc2.domain.tld:636/');
 
    $Self->{'AuthModule::ConnectAD::Host'} = \@DCs;
    # specify the failover timeout in seconds
    $Self->{'Customer::AuthModule::ConnectAD::Params'}    = {
        timeout => 2,
    }; 
````