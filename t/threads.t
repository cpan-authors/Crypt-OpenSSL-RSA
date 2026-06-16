use strict;
use warnings;
use Test::More;
use Config;

BEGIN {
    if (!$Config{useithreads}) {
        plan skip_all => 'perl not built with ithreads';
    }
    eval 'require threads; threads->import()';
    if ($@) {
        plan skip_all => "threads not available: $@";
    }
}
use Crypt::OpenSSL::Random;
use Crypt::OpenSSL::RSA;

plan tests => 4;

Crypt::OpenSSL::Random::random_seed("OpenSSL needs at least 32 bytes.");
Crypt::OpenSSL::RSA->import_random_seed();

ok(Crypt::OpenSSL::RSA->can('CLONE_SKIP'),
    "CLONE_SKIP is defined");
is(Crypt::OpenSSL::RSA->CLONE_SKIP, 1,
    "CLONE_SKIP returns 1");

my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);
my $pub_pem = $rsa->get_public_key_x509_string();

my $thr = threads->create(sub {
    my $child_rsa = Crypt::OpenSSL::RSA->generate_key(2048);
    return $child_rsa->get_public_key_x509_string();
});

my $child_pub = $thr->join();
ok(defined $child_pub && $child_pub =~ /^-----BEGIN PUBLIC KEY-----/,
    "child thread can independently generate and export keys");

ok($rsa->get_public_key_x509_string() eq $pub_pem,
    "parent RSA object undamaged after child thread exit");
