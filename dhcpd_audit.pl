#!/usr/bin/perl

###################################################
### dhcpd_audit.pl								###
### Look for changes to dhcpd leases file and	###
### send notifications.							###
### A. Caravello. 11/1/2016						###
###################################################

# Load Modules
use strict;
use DBI;
use Data::Dumper;
use Time::Local;
use Net::SMTP::SSL;

###################################################
### User Configurable Parameters				###
###################################################
# Default Config
my %config = (
	'leases'		=> '/var/lib/dhcpd/dhcpd.leases',
	'database'		=> '/var/lib/dhcpd.sq3',
	'log_level'		=> 'info',
	'from_address'	=> '',
	'notify_email'	=> '',
	'smtp_host'		=> '',
	'smtp_port'		=> '',
	'smtp_user'		=> '',
	'smtp_pass'		=> '',
);

# Load Command Line Options
foreach my $argument(@ARGV) {
	chomp $argument;
	if ($argument =~ /^\-\-config\-file\=(.*)/) {
		# Load Specified Config File
		load_config($1);
	}
	elsif ($argument =~ /^\-\-(leases|database|log\-level|notify\-email)\=(.*)/) {
		# Parse and Store Parameters
		my $param = $1;
		my $value = $2;
		$param =~ s/\-/_/g;
		$config{$param} = $value;
	}
}

notify('dhcpd_audit.pl starting at '.datetime(),'info');
###################################################
### Prepare Database Connections and Queries	###
###################################################
my $dbh = DBI->connect(
	"DBI:SQLite:dbname=".$config{database},
	'',
	'',
	{	PrintError => 0,
		RaiseError => 0,
		sqlite_use_immediate_transaction => 1
	}
);
unless ($dbh) {
	notify("Could not connect to database: ".DBI->errstr,'error');
	exit 1;
}

my $create_database_query = "
	CREATE	TABLE IF NOT EXISTS leases (
		`ip_address` VARCHAR NOT NULL UNIQUE,
		`hostname` VARCHAR NOT NULL,
		`time_start` INT NOT NULL,
		`time_end` INT NOT NULL,
		`mac_address` VARCHAR NOT NULL UNIQUE
	)
";
my $create_database = $dbh->prepare($create_database_query)
	or die "Cannot prepare query to create database: ".DBI->errstr."\n";

my $get_lease_by_name_query = "
	SELECT	*
	FROM	leases
	WHERE	`hostname` = ?
";
my $get_lease_by_name = $dbh->prepare($get_lease_by_name_query)
	or die "Cannot prepare query to get lease by name: ".DBI->errstr."\n";

my $get_lease_by_ip_query = "
	SELECT	*
	FROM	leases
	WHERE	`ip_address` = ?
";
my $get_lease_by_ip = $dbh->prepare($get_lease_by_ip_query)
	or die "Cannot prepare query to get lease by ip: ".DBI->errstr."\n";

my $get_lease_by_mac_query = "
	SELECT	*
	FROM	leases
	WHERE	`mac_address` = ?
";
my $get_lease_by_mac = $dbh->prepare($get_lease_by_mac_query)
	or die "Cannot prepare query to get lease by mac: ".DBI->errstr."\n";

my $add_lease_query = "
	INSERT
	INTO	leases
	(		`ip_address`,
			`hostname`,
			`time_start`,
			`time_end`,
			`mac_address`
	)
	VALUES
	(		?,?,?,?,?)
";
my $add_lease = $dbh->prepare($add_lease_query)
	or die "Cannot prepare query to add lease: ".DBI->errstr."\n";

my $update_lease_query = "
	UPDATE	leases
	SET		`ip_address` = ?,
			`hostname` = ?,
			`time_start` = ?,
			`time_end` = ?
	WHERE	`mac_address` = ?
";
my $update_lease = $dbh->prepare($update_lease_query)
	or die "Cannot prepare query to update lease: ".DBI->errstr."\n";

my $get_expired_query = "
	SELECT	*
	FROM	leases
	WHERE	time_end < ?
";
my $get_expired = $dbh->prepare($get_expired_query)
	or die "Cannot prepare query to get leases: ".DBI->errstr."\n";

my $delete_lease_query = "
	DELETE
	FROM	leases
	WHERE	mac_address = ?
";
my $delete_lease = $dbh->prepare($delete_lease_query)
	or die "Cannot prepare query to delete lease: ".DBI->errstr."\n";

###################################################
### Main Procedure								###
###################################################
# Create Database if not already there
$create_database->execute()
	or die "Cannot create database: ".DBI->errstr."\n";

# Load Leases File
if (! open(LEASES,$config{'leases'})) {
	notify("Could not open leases file: $!",'error');
	exit 1;
}
my @records = <LEASES>;
close LEASES;

my %lease;
foreach my $record(@records) {
	# Remove Trailing LineFeed
	chomp $record;

	# Remove Comments
	$record =~ s/\#.*//;

	# Skip empty records
	next unless ($record);

	if ($record =~ /^\}$/) {
		#print Dumper %lease;
		if ($lease{'mac_address'}) {
			# Validate Record
			unless ($lease{'time_end'} >= time) {
				next;
			}
			unless ($lease{'hostname'}) {
				$lease{'hostname'} = '[null]';
			}

			# See if Address already in use
			$get_lease_by_ip->execute($lease{ip_address});
			if (DBI->errstr) {
				notify("Error checking database for used address: ".DBI->errstr,'error');
				exit 1;
			}
			while (my $conflict = $get_lease_by_ip->fetchrow_hashref()) {
				if ($conflict->{mac_address}) {
					if ($conflict->{time_end} < time) {
						# Delete Expired Lease
						$delete_lease->execute($conflict->{mac_address});
						if (DBI->errstr) {
							notify("Error deleting lease: ".DBI->errstr,'error');
							exit 1;
						}
					}
				}
			}

			# See if lease exists
			$get_lease_by_mac->execute($lease{'mac_address'});
			if (DBI->errstr) {
				notify("Error checking database for existing lease: ".DBI->errstr,'error');
				exit 1;
			}
			my $found = $get_lease_by_mac->fetchrow_hashref();
			if ($found->{mac_address}) {
				notify("Lease exists for host '".$found->{'hostname'}."'",'debug');

				# See if anything has changed
				my $message = '';
				if ($found->{hostname} ne $lease{hostname}) {
					$message .= "\n" if ($message);
					$message .= "Hostname changed to '".$lease{'hostname'}."' from '".$found->{hostname}."'";
				}
				if ($found->{time_start} > $lease{time_start}) {
					$message .= "\n" if ($message);
					$message .= "Start time changed to '".datetime($lease{'time_start'})."' from '".datetime($found->{time_start})."'";
				}
				if ($found->{time_end} > $lease{time_end}) {
					$message .= "\n" if ($message);
					$message .= "End time changed to '".datetime($lease{'time_end'})."' from '".datetime($found->{time_end})."'";
				}
				if ($found->{ip_address} ne $lease{ip_address}) {
					$message .= "\n" if ($message);
					$message .= "IP Address changed to '".$lease{'ip_address'}."' from '".$found->{ip_address}."'";
				}
				if ($message) {
					notify("Lease updated: \n".$message,'notice');
					$update_lease->execute(
						$lease{ip_address},
						$lease{hostname},
						$lease{time_start},
						$lease{time_end},
						$lease{mac_address}
					);
					if (DBI->errstr) {
						notify("Error updating lease: ".DBI->errstr,'error');
					}
				}
			}
			else {
				notify("New lease granted to ".$lease{hostname}." [".$lease{mac_address}."] at ".$lease{ip_address},"notice");
				$add_lease->execute(
					$lease{ip_address},
					$lease{hostname},
					$lease{time_start},
					$lease{time_end},
					$lease{mac_address}
				);
				if (DBI->errstr) {
					notify("Error adding lease: ".DBI->errstr,'error');
				}
			}
			undef(%lease);
		}
		else {
			notify("Trailing curly bracket out of place in leases file",'warning');
		}
	}
	elsif ($record =~ /^lease\s([\d\.]+)\s\{/) {
		$lease{ip_address} = $1;
	}
	elsif ($record =~ /^\s+starts\s\d+\s(\d+\/\d+\/\d+\s\d+\:\d+\:\d+)\;/) {
		my $datetime = $1;
		$lease{time_start} = timestamp($datetime);
	}
	elsif ($record =~ /^\s+ends\s\d+\s(\d+\/\d+\/\d+\s\d+\:\d+\:\d+)\;/) {
		my $datetime = $1;
		$lease{time_end} = timestamp($datetime);
	}
	elsif ($record =~ /^\s+client\-hostname\s\"(.+)\"\;/) {
		$lease{hostname} = $1;
	}
	elsif ($record =~ /^\s+hardware\sethernet\s([\w\:]+)\;/) {
		$lease{mac_address} = $1;
	}
	elsif ($record =~ /^\s+(cltt|binding|uid|set|next|tstp)\s.*\;/) {
		next;
	}
	elsif ($record =~ /^(server\-duid)\s.*\;/) {
		next;
	}
	else {
		notify("Unrecognized record: ".$record,'debug');
	}
}

# Clean up
$get_expired->execute(time);
while (my $lease = $get_expired->fetchrow_hashref()) {
	my ($sec,$min,$hour,$day,$mon,$year) = localtime($lease->{time_end});
	my $expires = sprintf("%04d-%02d-%02d %02d:%02d:%02d",$year + 1900,$mon + 1,$day,$hour,$min,$sec);
	notify("IP Address ".$lease->{ip_address}." for ".$lease->{hostname}." expires: $expires");

	# Delete Expired Lease
	$delete_lease->execute($lease->{mac_address});
	if (DBI->errstr) {
		notify("Error deleting lease: ".DBI->errstr,'error');
		exit 1;
	}
}
###################################################
### Subroutines									###
###################################################
sub notify {
	my ($message,$level) = @_;
	$level = 'info' unless ($level);
	$level = lc($level);
	return if ($level eq 'debug' && $config{log_level} =~ /^(info|notice|warning|error)$/);
	return if ($level eq 'info' && $config{log_level} =~ /^(notice|warning|error)$/);
	printf ("[%s] %s: %s\n",datetime(),$level,$message);
	return unless ($config{from_address} && $config{notify_email});

	return;
	#return if ($level =~ /(debug|info)/);
	my $smtp;
	unless ($smtp = Net::SMTP::SSL->new(
		$config{smtp_host},
		Port	=> $config{smtp_port}
	)) {
		die "Cannot connect to mail server '".$config{smtp_host}."'\n";
	}
	unless ($smtp->auth($config{smtp_user},$config{smtp_pass})) {
		die "Cannot authenticate to mail server\n";
	}
	
	$smtp->mail($config{from_address});
	$smtp->to($config{notify_email});
	$smtp->data("Subject: ".$level." message from dhcpd audit.\r\n$message\r\n");
	$smtp->quit;
}

sub datetime {
	my $timestamp = shift;
	$timestamp = time unless ($timestamp);
	my ($sec,$min,$hour,$day,$month,$year) = localtime($timestamp);
	$month += 1;
	$year += 1900;
	return sprintf("%04d-%02d-%02d %02d:%02d:%02d",$year,$month,$day,$hour,$min,$sec);
}

sub timestamp {
	my $datetime = shift;
	my ($year,$month,$day,$hour,$min,$sec) = split(/[\s\/\:]/, $datetime);
	my $timestamp = timelocal($sec,$min,$hour,$day,$month-1,$year);
	return $timestamp;
}

sub load_config {
	my ($file) = shift;
	
	die "Config file not found\n" unless (-e $file);

	# Load Content From File
	open(CONFIG,$file)
		or die "Cannot open config file: $!\n";

	my @records = <CONFIG>;
	close CONFIG;
	
	# Load Configurations
	foreach my $record(@records) {
		chomp $record;
		$record =~ s/\#.*//;
		$record =~ s/^\;.*//;
		next unless ($record);
		if ($record =~ /^\s*(leases|database|log_level|notify_email|smtp_host|smtp_port|smtp_user|smtp_pass|from_address)\s*\=\s*(.*)/) {
			$config{$1} = $2;
		}
	}
}
