use strict;
use warnings;
use Test::More;

use Crypt::OpenSSL::Random;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Guess qw(openssl_version);

Crypt::OpenSSL::Random::random_seed("OpenSSL needs at least 32 bytes.");
Crypt::OpenSSL::RSA->import_random_seed();

my $HAS_BIGNUM = eval { require Crypt::OpenSSL::Bignum; 1 } ? 1 : 0;
my ($major) = openssl_version();

my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);

# ===================================================================
# new_key_from_parameters with check => 1
# ===================================================================
# The check option validates key consistency after construction.
# It should pass for valid keys and croak for invalid ones.

SKIP: {
    skip "Crypt::OpenSSL::Bignum required for check option tests", 5
        unless $HAS_BIGNUM;

    my ($n, $e, $d, $p, $q) = $rsa->get_key_parameters();

    # Valid key with check => 1 should succeed
    my $rsa_checked = eval {
        Crypt::OpenSSL::RSA->new_key_from_parameters($n, $e, $d, $p, $q, check => 1);
    };
    ok(!$@, "new_key_from_parameters(check => 1) succeeds with valid params")
        or diag "Error: $@";
    ok($rsa_checked && $rsa_checked->is_private(), "checked key is private");

    # Public-only key with check => 1 should succeed (check is skipped for public)
    my $rsa_pub_checked = eval {
        Crypt::OpenSSL::RSA->new_key_from_parameters($n, $e, undef, undef, undef, check => 1);
    };
    ok(!$@, "new_key_from_parameters(check => 1) succeeds for public-only key")
        or diag "Error: $@";
    ok($rsa_pub_checked && !$rsa_pub_checked->is_private(),
        "public-only key with check skips validation");

    # Without check option: default behavior (no validation)
    my $rsa_unchecked = eval {
        Crypt::OpenSSL::RSA->new_key_from_parameters($n, $e, $d, $p, $q);
    };
    ok(!$@, "new_key_from_parameters without check option succeeds");
}

# ===================================================================
# SSLv23 padding: Perl fallback on OpenSSL 3.x
# ===================================================================
# On 3.x, use_sslv23_padding is a Perl stub that croaks.
# On pre-3.x, it's defined in XS and should not croak.

{
    my $rsa_pad = Crypt::OpenSSL::RSA->generate_key(2048);
    eval { $rsa_pad->use_sslv23_padding() };
    if ($major >= 3) {
        like($@, qr/not available|removed/i,
            "use_sslv23_padding croaks on OpenSSL 3.x");
    }
    else {
        ok(!$@, "use_sslv23_padding does not croak on pre-3.x")
            or diag "Error: $@";
    }
}

# ===================================================================
# Subclassing: all constructors and operations
# ===================================================================
# make_rsa_obj() blesses into the caller's stash, supporting subclasses.
# Verify that constructor methods return blessed subclass objects and
# that all key operations work through the subclass.

{
    package Crypt::OpenSSL::RSA::TestSub;
    use base qw(Crypt::OpenSSL::RSA);
}

package main;

# generate_key returns subclass object
{
    my $sub_rsa = eval { Crypt::OpenSSL::RSA::TestSub->generate_key(2048) };
    ok(!$@, "subclass generate_key succeeds") or diag $@;
    isa_ok($sub_rsa, 'Crypt::OpenSSL::RSA::TestSub', "generate_key returns subclass");
    isa_ok($sub_rsa, 'Crypt::OpenSSL::RSA', "subclass isa base class");
    ok($sub_rsa->is_private(), "subclass key is private");
    ok($sub_rsa->check_key(), "subclass key passes check_key");

    # Export and reimport through subclass
    my $priv_pem = $sub_rsa->get_private_key_string();
    my $pub_pem  = $sub_rsa->get_public_key_string();

    my $sub_priv = eval { Crypt::OpenSSL::RSA::TestSub->new_private_key($priv_pem) };
    ok(!$@, "subclass new_private_key succeeds") or diag $@;
    isa_ok($sub_priv, 'Crypt::OpenSSL::RSA::TestSub',
        "new_private_key returns subclass");

    my $sub_pub = eval { Crypt::OpenSSL::RSA::TestSub->new_public_key($pub_pem) };
    ok(!$@, "subclass new_public_key succeeds") or diag $@;
    isa_ok($sub_pub, 'Crypt::OpenSSL::RSA::TestSub',
        "new_public_key returns subclass");

    # Encrypt/decrypt through subclass
    $sub_rsa->use_pkcs1_oaep_padding();
    $sub_pub->use_pkcs1_oaep_padding();
    my $ct = eval { $sub_pub->encrypt("subclass test") };
    ok(!$@, "subclass encrypt succeeds") or diag $@;
    my $pt = eval { $sub_rsa->decrypt($ct) };
    is($pt, "subclass test", "subclass decrypt round-trips");

    # Sign/verify through subclass
    $sub_rsa->use_pkcs1_pss_padding();
    $sub_pub->use_pkcs1_pss_padding();
    my $sig = eval { $sub_rsa->sign("subclass sign") };
    ok(!$@, "subclass sign succeeds") or diag $@;
    ok($sub_pub->verify("subclass sign", $sig), "subclass verify succeeds");
}

# new_public_key with X.509 format through subclass
{
    my $x509_pem = $rsa->get_public_key_x509_string();
    my $sub_x509 = eval { Crypt::OpenSSL::RSA::TestSub->new_public_key($x509_pem) };
    ok(!$@, "subclass new_public_key with X.509 format succeeds") or diag $@;
    isa_ok($sub_x509, 'Crypt::OpenSSL::RSA::TestSub',
        "X.509 new_public_key returns subclass");
}

# new_key_from_parameters through subclass
SKIP: {
    skip "Crypt::OpenSSL::Bignum required for subclass parameter test", 2
        unless $HAS_BIGNUM;

    my ($n, $e) = $rsa->get_key_parameters();
    my $sub_params = eval {
        Crypt::OpenSSL::RSA::TestSub->new_key_from_parameters($n, $e);
    };
    ok(!$@, "subclass new_key_from_parameters succeeds") or diag $@;
    isa_ok($sub_params, 'Crypt::OpenSSL::RSA::TestSub',
        "new_key_from_parameters returns subclass");
}

# ===================================================================
# Binary payloads with NUL bytes
# ===================================================================
# Ensure NUL bytes in plaintext survive encrypt/decrypt round-trip.

{
    my $rsa_bin = Crypt::OpenSSL::RSA->generate_key(2048);

    # OAEP: binary data with embedded NULs
    $rsa_bin->use_pkcs1_oaep_padding();
    my $nul_data = "before\x00middle\x00after";
    my $ct = $rsa_bin->encrypt($nul_data);
    my $pt = $rsa_bin->decrypt($ct);
    is($pt, $nul_data, "OAEP: NUL bytes in plaintext survive round-trip");
    is(length($pt), length($nul_data),
        "OAEP: decrypted length matches (NULs preserved)");

    # All-zero payload
    my $zeros = "\x00" x 10;
    $ct = $rsa_bin->encrypt($zeros);
    $pt = $rsa_bin->decrypt($ct);
    is($pt, $zeros, "OAEP: all-zero payload round-trips");
    is(length($pt), 10, "OAEP: all-zero payload length preserved");

    # Single byte
    $ct = $rsa_bin->encrypt("\x42");
    $pt = $rsa_bin->decrypt($ct);
    is($pt, "\x42", "OAEP: single byte round-trips");

    # No-padding: binary data
    $rsa_bin->use_no_padding();
    my $block_size = $rsa_bin->size();
    my $nul_block = "\x00" x ($block_size - 1) . "\x01";
    $ct = $rsa_bin->encrypt($nul_block);
    $pt = $rsa_bin->decrypt($ct);
    is($pt, $nul_block, "no-padding: NUL-heavy block round-trips");
}

# ===================================================================
# Sign/verify with binary data containing NUL bytes
# ===================================================================

{
    my $rsa_sig = Crypt::OpenSSL::RSA->generate_key(2048);
    $rsa_sig->use_pkcs1_pss_padding();

    my $nul_msg = "data\x00with\x00nuls";
    my $sig = $rsa_sig->sign($nul_msg);
    ok($rsa_sig->verify($nul_msg, $sig),
        "PSS: signature of NUL-containing message verifies");

    # Truncating at NUL should fail verification
    ok(!$rsa_sig->verify("data", $sig),
        "PSS: truncated-at-NUL message does not verify");

    # All-zero message
    my $zero_msg = "\x00\x00\x00";
    my $zero_sig = $rsa_sig->sign($zero_msg);
    ok($rsa_sig->verify($zero_msg, $zero_sig),
        "PSS: all-zero message signature verifies");
    ok(!$rsa_sig->verify("", $zero_sig),
        "PSS: all-zero signature does not verify empty string");
}

# ===================================================================
# private_encrypt/public_decrypt with binary data
# ===================================================================

{
    my $rsa_pe = Crypt::OpenSSL::RSA->generate_key(2048);
    $rsa_pe->use_pkcs1_padding();
    my $pub_pe = Crypt::OpenSSL::RSA->new_public_key($rsa_pe->get_public_key_string());
    $pub_pe->use_pkcs1_padding();

    my $nul_data = "priv\x00encrypt\x00test";
    my $ct = $rsa_pe->private_encrypt($nul_data);
    my $pt = $pub_pe->public_decrypt($ct);
    is($pt, $nul_data,
        "private_encrypt/public_decrypt: NUL bytes survive round-trip");
}

done_testing;
