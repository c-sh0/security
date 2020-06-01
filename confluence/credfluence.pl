#!/usr/bin/perl
#
# Confluence Credential Finder
#
# Use Confluence REST API to scan page data looking for password information.
# Like any credential scanner, it works pretty well however, having to consider
# all the corner cases, it is by no means perfect. There are a lot of
# free tools for finding credentials/secrets in source code but i could
# not find any for confluence.
#
# Notes:
#
#  * Clean up the regex rabbit hole. Having to account for user wiki
#    sytles, grammer, misspelling, coding styles etc.. becomes
#    a liitle daunting. Off the shelf XML/HTML perl modules also
#    didn't quite work as expected:
#
#    "Confluence storage format does not comply with the XHTML definition.
#    In particular, Confluence includes custom elements for macros and more."
#    https://confluence.atlassian.com/doc/confluence-storage-format-790796544.html
#
#    There is a module called HTML::WikiConverter::Confluence (it looks
#    limited) https://metacpan.org/release/DIBERRI/HTML-WikiConverter-Confluence-0.01
#
#    Improve algorithm vs dictionary word's vs mixed chars credential detection?
#    Instead of using regex, maybe some kind of user to word frequency analysis?
#    ML framework?
#
# Additional References:
# ---------------------------------
# -: Is Confluence safe enough to store passwords?
#    https://community.atlassian.com/t5/Confluence-questions/Is-Confluence-safe-enough-to-store-passwords/qaq-p/49286
#
# -: Confluence Server REST API
#    https://developer.atlassian.com/server/confluence/confluence-server-rest-api/#advanced-search-through-cql
#
# -: Detecting secrets in source code
#    https://auth0.engineering/detecting-secrets-in-source-code-bd63b0fe4921
#
# -csh
# 04/05/2020
#
use strict;
use warnings;
use open qw(:std :utf8);
use Getopt::Long;
use URI::Encode;
use Regexp::Common;
use REST::Client;
use MIME::Base64;
use JSON::XS;
use JSON;
use Data::Dumper;

my($opt_Host);
my($opt_Login);
my($opt_CQL);
my($opt_Pageid);
my(%opt_SkipIds);
my($opt_Skipf)	 = undef;
my($opt_Entropy) = 4.0; # default
# debug single page by ID only.
# pass --debug at command line w/ --pageid
my($opt_DEBUG) = -1;

sub help {
print << "_EOF_";
==================================================================
[/csh:]>               _    ___ _   Confluence Credential Finder
                      | |  / __) |
  ____  ____ _____  __| |_| |__| | _   _ _____ ____   ____ _____
 / ___)/ ___) ___ |/ _  (_   __) || | | | ___ |  _ \\ / ___) ___ |
( (___| |   | ____( (_| | | |  | || |_| | ____| | | ( (___| ____|
 \\____)_|   |_____)\\____| |_|   \\_)____/|_____)_| |_|\\____)_____)

==================================================================
Usage: $0 [options...]

  Required:
	--host   [http(s)://host] - host url
	--login  [user:pass|jsessionid] - Basic Auth user:pass or JSESSIONID cookie
	--cql    [cql query] - confluence CQL query

  Optional:
	--skipf   [file]   - skip pages file, (page id's per line) good for false positives
	--pageid  [pageid] - single page scan
	--entropy [n.nnnn] - Show only potential secrets with an entropy >= n.nn (default: 4.0)

  Example:
      * Scan all confluence pages returned by a text search for "password", use JSESSIONID cookie value,
	and show only strings with an entropy >= 3.312

 	  $0 --host https://127.0.0.1 --login AABBCCDDEE55661 --entropy 3.312 --cql text~"password" --entropy 3.312

_EOF_
	exit(-1);
}

GetOptions(
	"login=s"	=> \$opt_Login,	  # Required - Authentication (user:pass or JESSIONID)
	"host=s"	=> \$opt_Host,	  # Required - Host (ie: http(s)://host.com)
	"cql=s"		=> \$opt_CQL,	  # Required - Confluence query (CQL statement)
	"skipf=s"	=> \$opt_Skipf,	  # Optional - Skip pages file by id's (page id per line)
	"entropy=f"	=> \$opt_Entropy, # Optional - Show secrets with an entropy >= n
	"pageid=i"	=> \$opt_Pageid,  # Optional - Scan contents for this page id only
	"debug=i"	=> \$opt_DEBUG,   # Hidden   - Debugging regex
) or help();

### check args
if(!defined $opt_Host || $opt_Host !~ m/^$RE{URI}{HTTP}{-scheme => 'https?'}$/) {
	print "Error: invalid --host\n";
	help();
}
# remove last '/' from --host if any
$opt_Host =~ s/\/\s*$//;

#
if(!defined $opt_CQL || !defined $opt_Login) {
	print "Error: missing required argument\n";
	help();
}

if(defined $opt_Pageid && defined $opt_Skipf) {
	print "Error: --skipf and --pageid cannot be used together\n";
	help();
}

if(defined $opt_Skipf) {
	if(! -e $opt_Skipf) {
		print "Error: $opt_Skipf $!\n";
		help();
	}

	open my $fh, '<', $opt_Skipf;
	chomp(my @SkipIds = <$fh>);
	close $fh;

	while(<@SkipIds>) {
		if($_ !~ /^$RE{num}{real}$/) {
			print "Error: invalid --skipf page id: $_\n";
			help();
		}
	}

	$opt_Skipf = 1;
	%opt_SkipIds = map { $_ => 1 } @SkipIds;

	#print Dumper(%opt_SkipIds);
}

# Request headers: Authentication and Content type
my($headers,$b64Str)	= undef;
my($user,$passwd)	= split(/:/,$opt_Login);

if(defined $user && defined $passwd) {
	$b64Str  = encode_base64("$user:$passwd",''); # https://www.perlmonks.org/?node_id=660422
	$headers = {Accept => 'application/json', Authorization => "Basic $b64Str"};
# JSESSIONID should be in $user after split
} elsif(defined $user && !defined $passwd) {
	$headers = {Accept => 'application/json', Cookie => "JSESSIONID=$user"};
} else {
	print "Error: invalid --login\n";
	help();
}

#############################################################################################
# Page count/depth. By default search results returned from the API is limited to 50
# next pageStart, increment += 50 at each iteration
my($pageStart)		= 0;
# Put a limit on the number of pages to parse. Limits of the number of
# API requests. If you want to parse every page returned, set this to a huge number.
# Note that  the script will also exit when no more pages (_links->next) are found.
# This is here mainly so we don't accidentally overwhelm the API. mileage may vary.
my($parseLimit)		= 1500;
# Setup API client
my($uriEncoder)		= URI::Encode->new();
my($restClient)		= REST::Client->new();
my($cqlQuery)		= $uriEncoder->encode("cql=$opt_CQL");	# URI encode the cql query
my($searchParams)	= 'expand=body.storage,version,history'; # expand content body,version,history
#
#my($format)		= HTML::FormatText::WithLinks->new();

# Set host and api search path
if(defined $opt_Pageid) {
	$restClient->setHost("$opt_Host/rest/api/content/$opt_Pageid");
} else {
	$restClient->setHost("$opt_Host/rest/api/content/search");
}
#

while($pageStart <= $parseLimit) {
	my($searchResults);
	my($responseCode);

	# Send request:
	if(defined $opt_Pageid) { # single page request
		$restClient->GET("?$searchParams", $headers);
	} else {
		# mutiple page request, cql search
		$restClient->GET("?$searchParams&limit=50&start=$pageStart&cql=$opt_CQL", $headers);
	}

	# valid response ?
	$responseCode = $restClient->responseCode();
	if($responseCode != 200) {
		print "Oops! Something went wrong, HTTP Response code: $responseCode\n";
		exit(-1);
	}

	# https://metacpan.org/pod/JSON::XS#SECURITY-CONSIDERATIONS
	if(defined $opt_Pageid) { # single page request
        	@{$searchResults->{'results'}} = from_json($restClient->responseContent(),{ascii => 1});
	} else {
		# mutiple page request
        	$searchResults = from_json($restClient->responseContent(),{ascii => 1});
	}

	# Process results
        foreach my $pgHash (@{$searchResults->{'results'}}) {
		my($pgContent);
		my($pgText);
		my(@passWrds) = ();

		# skip this page
		if(defined $opt_Skipf && exists($opt_SkipIds{$pgHash->{'id'}})) {
			next;
		}

		# process content
		$pgContent = $pgHash->{'body'}->{'storage'}->{'value'};

		if($opt_DEBUG == 1 && $opt_Pageid) {
			print "opt_DEBUG ----------- Page before strip_tags() ---------------------\n";
			print Dumper($pgContent);
		}

		# clean up the txt
		$pgText = strip_tags($pgContent);

		# find passwords
		@passWrds = find_secrets($pgText,$opt_Entropy);

		if($opt_DEBUG == 1 && $opt_Pageid) {
			print "opt_DEBUG ----------- Page after strip_tags ---------------------\n";
			print Dumper($pgText);
			print "opt_DEBUG ----------- Detected Sectrets ---------------------\n";
			print Dumper(@passWrds);
		}

		if($passWrds[0]) {
			print "\n URL: $opt_Host$pgHash->{'_links'}->{'webui'}\n";
			print " Created by: $pgHash->{'history'}->{'createdBy'}->{'displayName'}\n";
			print " Last Modified by: $pgHash->{'version'}->{'by'}->{'displayName'}\n";
			print " PageId: $pgHash->{'id'}\n";
			print " Passwords found: ".scalar @passWrds."\n";
			print "\t ==:-------------------:==\n";
			foreach my $pswd (@passWrds) {
				print "\t\tpassword: $pswd (entropy: ".entropy_level($pswd).")\n";
			}
			print "\t ==:-------------------:==\n";
		}
	}

	# If there are no more pages to process, we're done.
	if(!defined $searchResults->{_links}->{'next'}) {
		print "\nNo more pages to process\nexit\n";
		exit(0);
	}

	# Increment next page start
	$pageStart += 50;
}

# I couldn't find a decent soution that worked well
sub strip_tags {
	my($in)  = @_;
	my($out) = $in;

	# Remove unwanted tags
	$out =~ s/<!\[CDATA\[/ /g; #CDATA tag
	$out =~ s/\]\]>/ /g;       # Closing CDATA tag
	$out =~ s/<(ac:.*?|\/ac:.*?)>/ /g;
	$out =~ s/<(span style=.*?|\/span.*?)>/ /g;
	$out =~ s/<(h[0-9]|\/h[0-9])>/ /g;
	$out =~ s/<h[0-9] class=.*?>/ /g;
	$out =~ s/<h[0-9] style=.*?>/ /g;
	$out =~ s/<(li|\/li)>/ /g;
	$out =~ s/<li style=.*?>/ /g;
	$out =~ s/<tr style=.*?>/ /g;
	$out =~ s/<li class=.*?>/ /g;
	$out =~ s/<(ol|\/ol)>/ /g;
	$out =~ s/<(u|\/u)>/ /g;
	$out =~ s/<u style=.*?>/ /g;
	$out =~ s/<(pre|\/pre)>/ /g;
	$out =~ s/<(code|\/code)>/ /g;
	$out =~ s/<code style=.*?>/ /g;
	$out =~ s/<code class=.*?>/ /g;
	$out =~ s/<tbody style=.*?>/ /g;
	$out =~ s/<(colgroup|\/colgroup)>/ /g;
	$out =~ s/<(col style=.*?|\/span.*?)>/ /g;
	$out =~ s/<col \/>/ /g;
	$out =~ s/<(blockquote|\/blockquote)>/ /g;
	$out =~ s/<(strong|\/strong)>/ /g;
	$out =~ s/<strong style=.*?>/ /g;
	$out =~ s/<(p|\/p)>/ /g;
	$out =~ s/<p class=.*?>//g;
	$out =~ s/<p align=.*?>//g;
	$out =~ s/<(em|\/em)>/ /g;
	$out =~ s/<(s|\/s)>/ /g;
	$out =~ s/<em style=.*?>/ /g;
	$out =~ s/<(br|br )\/>//g;
	$out =~ s/<(a href=.*?|\/a)>/ /g;
	$out =~ s/<a rel=.*?>/ /g;
	$out =~ s/<a class=.*?>/ /g;
	$out =~ s/<a title=.*?>/ /g;
	$out =~ s/<ri:page ri:.*?>/ /g;
	$out =~ s/<ri:url ri:.*?>/ /g;
	$out =~ s/<ri:attachment ri:.*?>/ /g;
	$out =~ s/<\/ri:attachment>/ /g;
	$out =~ s/<ri:user ri:.*?>/ /g;
	$out =~ s/<td colspan=.*?>/ /g;
	$out =~ s/<td class=.*?>/ /g;
	$out =~ s/<td style=.*?>/ /g;
	$out =~ s/<th colspan=.*?>/ /g;
	$out =~ s/<th style=.*?>/ /g;
	$out =~ s/<img class=.*?>/ /g;
	$out =~ s/<div class=.*?>/ /g;
	$out =~ s/<table class=.*?>/ /g;
	$out =~ s/<table style=.*?>/ /g;
	$out =~ s/<(ul|\/ul)>/ /g;
	$out =~ s/<ul style=.*?>/ /g;
	$out =~ s/<ul class=.*?>/ /g;
	$out =~ s/<br class=.*?>/ /g;
	$out =~ s/(&nbsp;|&amp;|&quot;|&ndash;|&lt;|&gt;)/ /g;
	$out =~ s/(<span .*?>|<span>)/ /g;
	$out =~ s/<(a|b|sub|title|dt|sup|thead|table|td|tbody|tr|div|th)>/ /g;
	$out =~ s/<\/(a|b|sub|title|dt|sup|thead|table|td|tbody|tr|div|th)>/ /g;
	$out =~ s/<p style=.*?>/ /g;
	$out =~ s/<a style=.*?>/ /g;
	$out =~ s/<hr style=.*?>/ /g;
	$out =~ s/<time datetime.*?>/ /g;

	# text cleanup
	$out =~ s/\t+/ /g; #replace tabs w/ single space
	$out =~ s/ +/ /g; #replace mutiple spaces w/ single space
	$out =~ s/^\s+|\s+$//g; #remove leading/trailing spaces

	return($out);
}

#
sub find_secrets {
	my($str,$e_level) = @_;
	my(@array);
	my(%tmp);
	my(@tmp1);

	# Database
	while($str =~ m/(IDENTIFIED\sBY\s.*?|PASSWORD\(|PASSWORD\sTO\s)([^\s]+)/ig) {
		if(defined $2) {
			if(entropy_level($2) >= $e_level) {
				push(@tmp1, $2);
			}
		}
	}

	# Device configuration secrets
	while($str =~ m/(password|secret|community|key)\s(1|5|7|8|2|sha512)\s([^\s]+)/ig) {
		if(defined $3) {
			if(entropy_level($3) >= $e_level) {
				push(@tmp1, $3);
			}
		}
	}

	# Detect *chars<chars+>string that are not device password {N..} hashes
	while($str =~ m/(password|community|key)(:|=|>\/|\\|\s|\s:\s|\s=\s|\s\/\s|:\s|=\s|\/\s)(?!1|5|7|8|2|sha512)([^\s]+)/ig) {
		if(defined $3) {
			if(entropy_level($3) >= $e_level) {
				push(@tmp1, $3);
			}
		}
	}

	# Detect varying pass**<chars+>**
	while($str =~ m/(passwd|pswd|pw|pass|passcode|root|admin|md5|token|secret|key_name|s\/n)(,|:|=|>|\/|\\|\s:\s|\s=\s|\s\/\s|:\s|=\s|\/\s)([^\s]+)/ig) {
		if(defined $3) {
			if(entropy_level($3) >= $e_level) {
				push(@tmp1, $3);
			}
		}
	}

	while($str =~ m/pass\sphrase(-|:|=|>|\/|:\s|=\s|\s:\s|\s=\s|\s\/\s|\s-\s)([^\s]+)/ig) {
		if(defined $2) {
			if(entropy_level($2) >= $e_level) {
				push(@tmp1, $2);
			}
		}
	}

	# Authorization Headers
	while($str =~ m/Authorization.*?(Basic|Bearer)\s([^\s]+)/g) {
		if(defined $2) {
			if(entropy_level($2) >= $e_level) {
				push(@tmp1, $2);
			}
		}
	}

	# email,passwd combo
	while($str =~ m/([a-zA-Z][\w\_\.])\@([a-zA-Z0-9.-]+)\.([a-zA-Z]{2,4})(\s:\s|:\s|\s=\s|=\s|\s\/\s|\/\s|=|:|\/)([^\s]+)/ig) {
		if(defined $5) {
			if(entropy_level($5) >= $e_level) {
				push(@tmp1, $5);
			}
		}
	}

	# ssh/ssl
	while($str =~ m/PRIVATE KEY-----\s([^\s]+)/ig) {
		if(defined $1) {
			if(entropy_level($1) >= $e_level) {
				push(@tmp1, $1);
			}
		}
	}

	# Random config's/settings/scripts etc..
	while($str =~ m/({default_pass,|{passcode,)(.*?\})/ig) {
		if(defined $2) {
			if(entropy_level($2) >= $e_level) {
				push(@tmp1, $2);
			}
		}
	}
	while($str =~ m/(DesCrypt.decrypt|element.login)(.*?\))/ig) {
		if(defined $2) {
			if(entropy_level($2) >= $e_level) {
				push(@tmp1, $2);
			}
		}
	}
	while($str =~ m/<password>(.*?>)/ig) {
		if(defined $1) {
			if(entropy_level($1) >= $e_level) {
				push(@tmp1, $1);
			}
		}
	}
	while($str =~ m/("access_key":\s|"secret_key":\s)([^\s]+)/ig) {
		if(defined $2) {
			if(entropy_level($2) >= $e_level) {
				push(@tmp1, $2);
			}
		}
	}
	# command line args (too many false positives)
	#while($str =~ m/(-k|-p|-u)(:|=|:\s|=\s|\s)([^\s]+)/ig) {
	#	if(defined $3) {
	#		if(entropy_level($3) >= $e_level) {
	#			push(@tmp1, $3);
	#		}
	#	}
	#}
	# IPMI
	while($str =~ m/(lan\sset\s1\ssnmp\s|SNMP\sCommunity\sString\s:\s)([^\s]+)/ig) {
		if(defined $2) {
			if(entropy_level($2) >= $e_level) {
				push(@tmp1, $2);
			}
		}
	}

	# make uniq
	%tmp   = map { $_, 1 } @tmp1;
	@array = keys %tmp;

	# Uhg, lame, remove any urls
	@array = grep(!/http/, @array);

	return @array;
}

# Shannon Entropy Calculator
# http://etutorials.org/Misc/blast/Part+II+Theory/Chapter+4.+Sequence+Similarity/4.1+Introduction+to+Information+Theory/
sub entropy_level {
	my($psswd) = @_;
	my($total) = 0;  # total symbols counted
	my($H)     = 0;  # H is the entropy
	my(%Count);      # stores the counts of each symbol

	foreach my $char (split(//, $psswd)) { # split the line into characters
		$Count{$char}++;               # add one to this character count
		$total++;                      # add one to total counts
	}

	foreach my $char (keys %Count) {      # iterate through characters
		my $p = $Count{$char}/$total; # probability of character
		$H += $p * log($p);           # p * log(p)
	}

	$H = -$H/log(2); # negate sum, convert base e to base 2
	#print "Entropy: $psswd = $H bits\n"; # output
	return $H;
}

