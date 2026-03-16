use strict;
use Test::More;

use Crypt::OpenSSL::Random;
use Crypt::OpenSSL::RSA;

Crypt::OpenSSL::Random::random_seed("OpenSSL needs at least 32 bytes.");
Crypt::OpenSSL::RSA->import_random_seed();

my $HAS_BIGNUM = $INC{'Crypt/OpenSSL/Bignum.pm'} ? 1 : 0;

plan tests => 9 + ($HAS_BIGNUM ? 14 : 0);

# --- Cross-key operations ---
# Sign with key1, verify with key2 — should return false, not croak.

my $rsa1 = Crypt::OpenSSL::RSA->generate_key(2048);
my $rsa2 = Crypt::OpenSSL::RSA->generate_key(2048);

$rsa1->use_pkcs1_pss_padding();
$rsa2->use_pkcs1_pss_padding();

my $plaintext = "The quick brown fox jumps over the lazy dog";

my $sig1 = $rsa1->sign($plaintext);
ok( defined $sig1 && length($sig1) > 0, "sign with key1 produces signature" );

my $cross_verify = eval { $rsa2->verify($plaintext, $sig1) };
ok( !$@, "cross-key verify does not croak" );
ok( !$cross_verify, "cross-key verify returns false (key1 sig, key2 verify)" );

# Sign with key2, verify with key1
my $sig2 = $rsa2->sign($plaintext);
$cross_verify = eval { $rsa1->verify($plaintext, $sig2) };
ok( !$@, "reverse cross-key verify does not croak" );
ok( !$cross_verify, "reverse cross-key verify returns false" );

# Same key should verify its own signature
ok( $rsa1->verify($plaintext, $sig1), "key1 verifies its own signature" );
ok( $rsa2->verify($plaintext, $sig2), "key2 verifies its own signature" );

# --- Key export → import → sign/verify round-trip ---

my $priv_pem  = $rsa1->get_private_key_string();
my $pub_pem   = $rsa1->get_public_key_string();
my $rsa1_copy = Crypt::OpenSSL::RSA->new_private_key($priv_pem);
my $rsa1_pub  = Crypt::OpenSSL::RSA->new_public_key($pub_pem);

$rsa1_copy->use_pkcs1_pss_padding();
$rsa1_pub->use_pkcs1_pss_padding();

my $sig_copy = $rsa1_copy->sign($plaintext);
ok( $rsa1_pub->verify($plaintext, $sig_copy),
    "exported private key signs, exported public key verifies" );
ok( $rsa1->verify($plaintext, $sig_copy),
    "original key verifies signature from exported key" );

# --- Key parameter round-trip with real-sized keys ---
# Requires Crypt::OpenSSL::Bignum

SKIP: {
    skip "Crypt::OpenSSL::Bignum required for parameter tests", 14
        unless $HAS_BIGNUM;

    # Extract parameters from a 2048-bit key
    my ($n, $e, $d, $p, $q, $dmp1, $dmq1, $iqmp) = $rsa1->get_key_parameters();

    ok( defined $n && defined $e, "get_key_parameters returns n and e" );
    ok( defined $d, "get_key_parameters returns d for private key" );
    ok( defined $p && defined $q, "get_key_parameters returns p and q" );
    ok( defined $dmp1 && defined $dmq1 && defined $iqmp,
        "get_key_parameters returns CRT params" );

    # Reconstruct from all parameters
    my $rsa_from_params = Crypt::OpenSSL::RSA->new_key_from_parameters($n, $e, $d, $p, $q);
    ok( $rsa_from_params, "new_key_from_parameters succeeds with full params" );
    is( $rsa_from_params->size(), $rsa1->size(),
        "reconstructed key has same size as original" );
    ok( $rsa_from_params->check_key(), "reconstructed key passes check_key()" );

    # Sign with reconstructed, verify with original
    $rsa_from_params->use_pkcs1_pss_padding();
    my $sig_params = $rsa_from_params->sign($plaintext);
    ok( $rsa1->verify($plaintext, $sig_params),
        "original key verifies signature from reconstructed key" );
    ok( $rsa_from_params->verify($plaintext, $sig1),
        "reconstructed key verifies signature from original key" );

    # Encrypt with reconstructed, decrypt with original
    $rsa_from_params->use_pkcs1_oaep_padding();
    $rsa1->use_pkcs1_oaep_padding();
    my $ct = $rsa_from_params->encrypt("secret message");
    my $pt = $rsa1->decrypt($ct);
    is( $pt, "secret message",
        "original key decrypts ciphertext from reconstructed key" );

    # Public-only key from parameters
    my $rsa_pub_params = Crypt::OpenSSL::RSA->new_key_from_parameters($n, $e);
    ok( $rsa_pub_params, "new_key_from_parameters with n,e only succeeds" );
    ok( !$rsa_pub_params->is_private(), "key from n,e only is not private" );

    $rsa_pub_params->use_pkcs1_pss_padding();
    eval { $rsa_pub_params->sign("hello") };
    like( $@, qr/Public keys cannot sign/,
        "public-only key from params cannot sign" );

    # Restore PSS for verification
    $rsa1->use_pkcs1_pss_padding();
    ok( $rsa_pub_params->verify($plaintext, $sig1),
        "public-only key from params verifies original signature" );
}
