# --
# Kernel/System/Auth/Sync/AD.pm / provides sync against Active Directory 
# with nested groups support, based on
# Kernel/System/Auth/LDAP.pm 
# Kernel/System/Auth/HTTPBasicAuth.pm - provides the $ENV authentication
#
# Copyright (C) 2001-2010 OTRS AG, http://otrs.org/
# Copyright (C) 2011 Shawn Poulson
# Copyright (C) 2011 Roy Kaldung <roy@kaldung.com>
# --
# This software comes with ABSOLUTELY NO WARRANTY. For details, see
# the enclosed file COPYING for license information (AGPL). If you
# did not receive this file, see http://www.gnu.org/licenses/agpl.txt.
# --
# Note:
#
# If you use this module with AuthType ENV, you should use as fallback the following
# config settings:
#
# If use isn't login through apache ($ENV{REMOTE_USER} or $ENV{HTTP_REMOTE_USER})
# $Self->{LoginURL} = 'http://host.example.com/not-authorised-for-otrs.html';
#
# $Self->{LogoutURL} = 'http://host.example.com/thanks-for-using-otrs.html';
# --

package Kernel::System::Auth::AD;

use strict;
use warnings;
use Net::LDAP;

use vars qw($VERSION);
$VERSION = qw($Revision: 1.16 $) [1];

sub new {
    my ( $Type, %Param ) = @_;

    # allocate new hash for object
    my $Self = {};
    bless( $Self, $Type );

    # check needed objects
    for (qw(LogObject ConfigObject DBObject)) {
        $Self->{$_} = $Param{$_} || die "No $_!";
    }

    # Debug 0=off 1=on
    $Self->{Debug} = 0;

    $Self->{Count} = $Param{Count} || '';

    # get ldap preferences
    $Self->{Count} = $Param{Count} || '';
    $Self->{Die} = $Self->{ConfigObject}->Get( 'AuthModule::AD::Die' . $Param{Count} );
    if ( $Self->{ConfigObject}->Get( 'AuthModule::AD::Host' . $Param{Count} ) ) {
        $Self->{Host} = $Self->{ConfigObject}->Get( 'AuthModule::AD::Host' . $Param{Count} );
    }
    else {
        $Self->{LogObject}->Log(
            Priority => 'error',
            Message  => "Need AuthModule::AD::Host$Param{Count} in Kernel/Config.pm",
        );
        return;
    }
    if ( defined( $Self->{ConfigObject}->Get( 'AuthModule::AD::BaseDN' . $Param{Count} ) ) ) {
        $Self->{BaseDN} = $Self->{ConfigObject}->Get( 'AuthModule::AD::BaseDN' . $Param{Count} );
    }
    else {
        $Self->{LogObject}->Log(
            Priority => 'error',
            Message  => "Need AuthModule::AD::BaseDN$Param{Count} in Kernel/Config.pm",
        );
        return;
    }
    if ( $Self->{ConfigObject}->Get( 'AuthModule::AD::UID' . $Param{Count} ) ) {
        $Self->{UID} = $Self->{ConfigObject}->Get( 'AuthModule::AD::UID' . $Param{Count} );
    }
    else {
        $Self->{LogObject}->Log(
            Priority => 'error',
            Message  => "Need AuthModule::AD::UID$Param{Count} in Kernel/Config.pm",
        );
        return;
    }

    if ( $Self->{ConfigObject}->Get( 'AuthModule::AD::AuthType' . $Param{Count} ) ) {
        $Self->{AuthType} = $Self->{ConfigObject}->Get( 'AuthModule::AD::AuthType' . $Param{Count} );
    }
    else {
        $Self->{LogObject}->Log(
            Priority => 'error',
            Message  => "Need AuthModule::AD::AuthType$Param{Count} in Kernel/Config.pm",
        );
        return;
    }
    if ( $Self->{AuthType} !~ m/(LOGIN|SSO)/ ) {
        $Self->{LogObject}->Log(
            Priority => 'error',
            Message  => "Wrong value for AuthModule::AD::AuthType$Param{Count} in Kernel/Config.pm",
        );
        return;
    }


    $Self->{SearchUserDN}
        = $Self->{ConfigObject}->Get( 'AuthModule::AD::SearchUserDN' . $Param{Count} ) || '';
    $Self->{SearchUserPw}
        = $Self->{ConfigObject}->Get( 'AuthModule::AD::SearchUserPw' . $Param{Count} ) || '';
    $Self->{GroupDN} = $Self->{ConfigObject}->Get( 'AuthModule::AD::GroupDN' . $Param{Count} )
        || '';
    $Self->{AccessAttr}
        = $Self->{ConfigObject}->Get( 'AuthModule::AD::AccessAttr' . $Param{Count} )
        || 'memberUid';
    $Self->{UserAttr} = $Self->{ConfigObject}->Get( 'AuthModule::AD::UserAttr' . $Param{Count} )
        || 'DN';
    $Self->{UserSuffix}
        = $Self->{ConfigObject}->Get( 'AuthModule::AD::UserSuffix' . $Param{Count} ) || '';
    $Self->{UserLowerCase}
        = $Self->{ConfigObject}->Get( 'AuthModule::AD::UserLowerCase' . $Param{Count} ) || 0;
    $Self->{DestCharset} = $Self->{ConfigObject}->Get( 'AuthModule::AD::Charset' . $Param{Count} )
        || 'utf-8';

    # ldap filter always used
    $Self->{AlwaysFilter}
        = $Self->{ConfigObject}->Get( 'AuthModule::AD::AlwaysFilter' . $Param{Count} ) || '';

    # Net::LDAP new params
    if ( $Self->{ConfigObject}->Get( 'AuthModule::AD::Params' . $Param{Count} ) ) {
        $Self->{Params} = $Self->{ConfigObject}->Get( 'AuthModule::AD::Params' . $Param{Count} );
    }
    else {
        $Self->{Params} = {};
    }

    return $Self;
}

sub GetOption {
    my ( $Self, %Param ) = @_;

    # check needed stuff
    if ( !$Param{What} ) {
        $Self->{LogObject}->Log( Priority => 'error', Message => "Need What!" );
        return;
    }

    # module options
    my %Option = ( PreAuth => 1, );

    # return option
    return $Option{ $Param{What} };
}

sub Auth_alt {
    my ( $Self, %Param ) = @_;

    # get params
    my $User       = $ENV{REMOTE_USER} || $ENV{HTTP_REMOTE_USER};
    my $RemoteAddr = $ENV{REMOTE_ADDR} || 'Got no REMOTE_ADDR env!';

    # return on no user
    if ( !$User ) {
        $Self->{LogObject}->Log(
            Priority => 'notice',
            Message =>
                "User: No \$ENV{REMOTE_USER} or \$ENV{HTTP_REMOTE_USER} !(REMOTE_ADDR: $RemoteAddr).",
        );
        return;
    }

    # replace login parts
    my $Replace = $Self->{ConfigObject}->Get(
        'AuthModule::HTTPBasicAuth::Replace' . $Self->{Count},
    );
    if ($Replace) {
        $User =~ s/^\Q$Replace\E//;
    }

    # regexp on login
    my $ReplaceRegExp = $Self->{ConfigObject}->Get(
        'AuthModule::HTTPBasicAuth::ReplaceRegExp' . $Self->{Count},
    );
    if ($ReplaceRegExp) {
        $User =~ s/$ReplaceRegExp/$1/;
    }

    # log
    $Self->{LogObject}->Log(
        Priority => 'notice',
        Message  => "User: $User authentication ok (REMOTE_ADDR: $RemoteAddr).",
    );

    # return login
    return $User;
}


sub Auth {
    my ( $Self, %Param ) = @_;

    # get params
    if ( $Self->{AuthType} eq "LOGIN" ) {
        $Param{User} = $Self->_ConvertTo( $Param{User}, $Self->{ConfigObject}->Get('DefaultCharset') );
        $Param{Pw}   = $Self->_ConvertTo( $Param{Pw},   $Self->{ConfigObject}->Get('DefaultCharset') );
    }
    else {
        $Param{User} = $ENV{REMOTE_USER} || $ENV{HTTP_REMOTE_USER};
    }
    my $RemoteAddr  = $ENV{REMOTE_ADDR} || 'Got no REMOTE_ADDR env!';

    # return on no user
    if ( !$Param{User} ) {
        $Self->{LogObject}->Log(
            Priority => 'notice',
            Message =>
                "User: No \$ENV{REMOTE_USER} or \$ENV{HTTP_REMOTE_USER} !(REMOTE_ADDR: $RemoteAddr).",
        );
        return;
    }

    # replace login parts
    my $Replace = $Self->{ConfigObject}->Get(
        'AuthModule::AD',
    );
    if ($Replace) {
        $Param{User} =~ s/^\Q$Replace\E//;
    }

    # regexp on login
    my $ReplaceRegExp = $Self->{ConfigObject}->Get(
        'AuthModule::AD',
    );
    if ($ReplaceRegExp) {
        $Param{User} =~ s/$ReplaceRegExp/$1/;
    }

    # remove leading and trailing spaces
    $Param{User} =~ s/^\s+//;
    $Param{User} =~ s/\s+$//;

    # Convert username to lower case letters
    if ( $Self->{UserLowerCase} ) {
        $Param{User} = lc $Param{User};
    }

    # add user suffix
    if ( $Self->{UserSuffix} ) {
        $Param{User} .= $Self->{UserSuffix};

        # just in case for debug
        if ( $Self->{Debug} > 0 ) {
            $Self->{LogObject}->Log(
                Priority => 'notice',
                Message  => "User: ($Param{User}) added $Self->{UserSuffix} to username!",
            );
        }
    }

    # ldap connect and bind (maybe with SearchUserDN and SearchUserPw)
    my $LDAP = Net::LDAP->new( $Self->{Host}, %{ $Self->{Params} } );
    if ( !$LDAP ) {
        if ( $Self->{Die} ) {
            die "Can't connect to $Self->{Host}: $@";
        }
        else {
            $Self->{LogObject}->Log(
                Priority => 'error',
                Message  => "Can't connect to $Self->{Host}: $@",
            );
            return;
        }
    }
    my $Result = '';
    if ( $Self->{SearchUserDN} && $Self->{SearchUserPw} ) {
        $Result = $LDAP->bind( dn => $Self->{SearchUserDN}, password => $Self->{SearchUserPw} );
    }
    else {
        $Result = $LDAP->bind();
    }
    if ( $Result->code ) {
        $Self->{LogObject}->Log(
            Priority => 'error',
            Message  => 'First bind failed! ' . $Result->error(),
        );
        $LDAP->disconnect;
        return;
    }

    # user quote
    my $UserQuote = $Param{User};
    $UserQuote =~ s/\\/\\\\/g;
    $UserQuote =~ s/\(/\\(/g;
    $UserQuote =~ s/\)/\\)/g;

    # build filter
    my $Filter = "($Self->{UID}=$UserQuote)";

    # prepare filter
    if ( $Self->{AlwaysFilter} ) {
        $Filter = "(&$Filter$Self->{AlwaysFilter})";
    }

    # perform user search
    $Result = $LDAP->search(
        base   => $Self->{BaseDN},
        filter => $Filter,
        attrs  => ['1.1'],
    );
    if ( $Result->code ) {
        $Self->{LogObject}->Log(
            Priority => 'error',
            Message  => 'Search failed! ' . $Result->error,
        );
        $LDAP->unbind;
        $LDAP->disconnect;
        return;
    }

    # get whole user dn
    my $UserDN = '';
    for my $Entry ( $Result->all_entries ) {
        $UserDN = $Entry->dn();
    }

    # log if there is no LDAP user entry
    if ( !$UserDN ) {

        # failed login note
        $Self->{LogObject}->Log(
            Priority => 'notice',
            Message  => "User: $Param{User} authentication failed, no LDAP entry found!"
                . "BaseDN='$Self->{BaseDN}', Filter='$Filter', (REMOTE_ADDR: $RemoteAddr).",
        );

        # take down session
        $LDAP->unbind;
        $LDAP->disconnect;
        return;
    }

    # DN quote
    my $UserDNQuote = $UserDN;
    $UserDNQuote =~ s/\\/\\\\/g;
    $UserDNQuote =~ s/\(/\\(/g;
    $UserDNQuote =~ s/\)/\\)/g;

    # check if user need to be in a group!
    if ( $Self->{GroupDN} ) {

        # just in case for debug
        #if ( $Self->{Debug} > 0 ) {
            $Self->{LogObject}->Log(
                Priority => 'notice',
                Message  => 'check for groupdn!',
            );
        #}

        # search if we're allowed to
	my $Result2 = _IsMemberOf($LDAP, $UserDN, $Self->{GroupDN});
	$Self->{LogObject}->Log(
		Priority => 'debug',
		Message => "UserDN $UserDN",
	);

        # log if there is no LDAP entry
        if ( !$Result2 ) {

            # failed login note
            $Self->{LogObject}->Log(
                Priority => 'notice',
                Message  => "User: $Param{User} authentication failed, no LDAP group entry found"
                    . "GroupDN='$Self->{GroupDN}', UserDN='$UserDN'! (REMOTE_ADDR: $RemoteAddr).",
            );

            # take down session
            $LDAP->unbind;
            $LDAP->disconnect;
            return;
        }
    }

    # login note
    $Self->{LogObject}->Log(
        Priority => 'notice',
        Message  => "User: $Param{User} ($UserDN) authentication ok (REMOTE_ADDR: $RemoteAddr).",
    );

    # take down session
    $LDAP->unbind;
    $LDAP->disconnect;
    return $Param{User};
}

sub _ConvertTo {
    my ( $Self, $Text, $Charset ) = @_;

    return if !defined $Text;

    if ( !$Charset || !$Self->{DestCharset} ) {
        $Self->{EncodeObject}->EncodeInput( \$Text );
        return $Text;
    }

    # convert from input charset ($Charset) to directory charset ($Self->{DestCharset})
    return $Self->{EncodeObject}->Convert(
        Text => $Text,
        From => $Charset,
        To   => $Self->{DestCharset},
    );
}

sub _ConvertFrom {
    my ( $Self, $Text, $Charset ) = @_;

    return if !defined $Text;

    if ( !$Charset || !$Self->{DestCharset} ) {
        $Self->{EncodeObject}->EncodeInput( \$Text );
        return $Text;
    }

    # convert from directory charset ($Self->{DestCharset}) to input charset ($Charset)
    return $Self->{EncodeObject}->Convert(
        Text => $Text,
        From => $Self->{DestCharset},
        To   => $Charset,
    );
}

sub _IsMemberOf($$$) {
   my ($ldap, $objectDN, $groupDN) = @_;
   return if ($groupDN eq "");

   my $groupSid = _GetSidByDN($ldap, $groupDN);
   return if ($groupSid eq "");

   my @matches = grep { $_ eq $groupSid } _GetTokenGroups($ldap, $objectDN);

   @matches > 0;
}

sub _GetTokenGroups($$) {
   my ($ldap, $objectDN) = @_;

   my $results = $ldap->search(
      base => $objectDN,
      scope => 'base',
      filter => '(objectCategory=*)',
      attrs => ['tokenGroups']
   );

   if ($results->count) {
      return $results->entry(0)->get_value('tokenGroups');
   }
}
sub _GetSidByDN($$) {
   my ($ldap, $objectDN) = @_;

   my $results = $ldap->search(
      base => $objectDN,
      scope => 'base',
      filter => '(objectCategory=*)',
      attrs => ['objectSid']
   );

   if ($results->count) {
      return $results->entry(0)->get_value('objectSid');
   }
}


1;
