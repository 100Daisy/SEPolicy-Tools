#!/usr/bin/perl -w

# This script accepts SELinux rules via STDIN (e.g. the output of audit2allow)
# and also by referencing an existing policy file. It merges the two to produce
# an output file which contains the contents of both sources.

use Getopt::Long;

# Set up some globals
my %output;
my @input_stdin;
my ($stdinname, $stdinver);

if (! -t STDIN ) {
	# Read in new SELinux rules from stdin
	while (<STDIN>) {
		chomp;
		push(@input_stdin, $_);
	}

	# Make sure STDIN is not blank
	if ($#input_stdin >= 1) {
		($stdinname, $stdinver) = get_header(@input_stdin);
	        # Filter the data into a nested hash for output
		&sort_output(@input_stdin);
	} else {
		print "no input from stdin\n";
		exit;
	}

	# Filter the data into a nested hash for output
	&sort_output(@input_stdin);
}

# Collect final printable output into an array
my @finaloutput = &print_output;

# Finally output the data as stdout
foreach (@finaloutput) {
	print $_;
}

sub print_output {
# Format the contents of the output hash into an array, ready for printing to file or stdout
	# Print allows
	#        $ALLOW                   $OBJECT       $CLASS $PROPERTY
	# #allow nagios_services_plugin_t dhcpd_state_t:file { read getattr open ioctl };
	foreach my $allow (sort keys %{$output{'allow'}}) {
		push (@output, "\n#============= $allow ==============\n");
		foreach my $object (sort keys %{$output{'allow'}{$allow}}) {
			foreach my $class (sort keys %{$output{'allow'}{$allow}{$object}}) {
				push (@output, "allow $allow $object:$class { ");
				foreach my $property (sort keys %{$output{'allow'}{$allow}{$object}{$class}}) {
					push (@output, "$property ");
				}
				push (@output, "};\n");
			}
		}
	}
	return @output;
}

sub sort_output {
# Spin through an array of SELinux config and sort it into a hierarchical hash
	my @input = @_;
	foreach my $line (@input) {
		#type rpm_exec_t;
		if ($line =~ m/^\s*type (\w+)/) {
			$output{'type'}{$1} = $1;
		#class file rename;
		} elsif ($line =~ m/^\s*class (\w+) (\w+);$/) {
			$output{'class'}{$1}{$2} = $2;
		#class file { rename execute setattr read lock create ioctl execute_no_trans write getattr unlink open append };
		} elsif ($line =~ m/^\s*class (\w+) \{ ([\s\w]+) \};$/) {
			my @arrayofclasses = split(/ /, $2);
			foreach my $class (@arrayofclasses) {
				$output{'class'}{$1}{$class} = $class;
			}
		#allow nagios_services_plugin_t dhcpd_state_t:file read;
		} elsif ($line =~ m/^\s*allow (\w+) (\w+):(\w+) (\w+);$/) {
			$output{'allow'}{$1}{$2}{$3}{$4} = $4;
		#allow nagios_services_plugin_t dhcpd_state_t:file { read getattr open ioctl };
	        } elsif ($line =~ m/^\s*allow (\w+) (\w+):(\w+) \{ ([\s\w]+) \};$/) {
			my @arrayofallows = split(/ /, $4);
			foreach my $allow (@arrayofallows) {
				$output{'allow'}{$1}{$2}{$3}{$allow} = $allow;
			}
		}
	}
}

sub get_header {
# Look at an array containing an SELinux policy and return
# the name and version of the policy, if it exists
	my @policy = @_;
	my $header = shift(@policy);
	chomp $header;

	# module resnet-nrpe 1.45;
	if ($header =~ m/^module ([a-z\-_]+) ([0-9\.]+);$/) {
		return ($1, $2);
	}
}
