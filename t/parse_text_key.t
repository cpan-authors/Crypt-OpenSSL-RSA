use strict;
use warnings;

use Crypt::OpenSSL::RSA;
use File::Temp qw/tempfile/;
use Test::More;

diag ("Version: $Crypt::OpenSSL::RSA::VERSION");

my ($priv_fh, $priv_file) = tempfile(UNLINK => 1);

my $priv = `openssl genrsa -out $priv_file 2>&1`;
my $priv_text = `openssl rsa -in $priv_file -text 2>&1`;

my $rsa = eval {
    Crypt::OpenSSL::RSA->new_private_key ($priv_text);
};

ok (defined ($rsa)) or diag ($@);

done_testing;
