use strict;
use warnings;
use Test::More;

use Crypt::OpenSSL::Random;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Guess qw(openssl_version);

Crypt::OpenSSL::Random::random_seed("OpenSSL needs at least 32 bytes.");
Crypt::OpenSSL::RSA->import_random_seed();

my ($major, $minor, $patch) = openssl_version();
my $is_3x = ($major ge '3.0' && defined $patch);

my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);
my $key_size = $rsa->size();
my $plaintext = "The quick brown fox jumps over the lazy dog";

# --- SHA-1 OAEP (default) round-trip works on all versions ---

$rsa->use_pkcs1_oaep_padding();
$rsa->use_sha1_oaep_hash();

my $ct_sha1 = $rsa->encrypt($plaintext);
ok(defined $ct_sha1, "OAEP SHA-1 encrypt succeeds");
is($rsa->decrypt($ct_sha1), $plaintext, "OAEP SHA-1 decrypt round-trips");

# --- SHA-256 OAEP ---

SKIP: {
    skip "OAEP with non-SHA1 hash requires OpenSSL 3.x", 6 unless $is_3x;

    $rsa->use_sha256_oaep_hash();

    my $ct_sha256 = $rsa->encrypt($plaintext);
    ok(defined $ct_sha256, "OAEP SHA-256 encrypt succeeds");
    is($rsa->decrypt($ct_sha256), $plaintext, "OAEP SHA-256 decrypt round-trips");

    # Mismatched hash: encrypt with SHA-256, decrypt with SHA-1
    $rsa->use_sha1_oaep_hash();
    eval { $rsa->decrypt($ct_sha256) };
    ok($@, "decrypt with wrong OAEP hash croaks");

    # Mismatched hash: encrypt with SHA-1, decrypt with SHA-256
    my $ct2 = $rsa->encrypt($plaintext);
    $rsa->use_sha256_oaep_hash();
    eval { $rsa->decrypt($ct2) };
    ok($@, "decrypt SHA-1 ciphertext with SHA-256 OAEP hash croaks");

    # Cross-key: encrypt with key1 SHA-256, decrypt with key2 SHA-256
    my $rsa2 = Crypt::OpenSSL::RSA->generate_key(2048);
    $rsa2->use_pkcs1_oaep_padding();
    $rsa2->use_sha256_oaep_hash();

    my $ct_k1 = $rsa->encrypt($plaintext);
    eval { $rsa2->decrypt($ct_k1) };
    ok($@, "decrypt with different key croaks even with matching OAEP hash");

    # SHA-256 with its own key pair round-trips
    my $ct_k2 = $rsa2->encrypt("secret");
    is($rsa2->decrypt($ct_k2), "secret", "SHA-256 OAEP round-trip with second key");
}

# --- SHA-512 OAEP (larger hash = smaller max message) ---

SKIP: {
    skip "OAEP with non-SHA1 hash requires OpenSSL 3.x", 3 unless $is_3x;

    $rsa->use_sha512_oaep_hash();

    my $max_sha512 = $key_size - 2 * 64 - 2;  # SHA-512 = 64 bytes
    my $ct_512 = $rsa->encrypt("x" x $max_sha512);
    ok(defined $ct_512, "OAEP SHA-512 encrypt at max size succeeds");
    is($rsa->decrypt($ct_512), "x" x $max_sha512,
       "OAEP SHA-512 round-trip at max size");

    eval { $rsa->encrypt("x" x ($max_sha512 + 1)) };
    like($@, qr/plaintext too long/,
         "OAEP SHA-512 rejects plaintext exceeding max size");
}

# --- Max message length varies correctly with OAEP hash ---

{
    my $max_sha1 = $key_size - 2 * 20 - 2;     # 214 for 2048-bit
    my $max_sha256 = $key_size - 2 * 32 - 2;    # 190 for 2048-bit
    my $max_sha512 = $key_size - 2 * 64 - 2;    # 126 for 2048-bit

    $rsa->use_sha1_oaep_hash();
    my $msg_sha1 = "x" x $max_sha1;
    my $ct = eval { $rsa->encrypt($msg_sha1) };
    ok(!$@, "SHA-1 OAEP max ($max_sha1 bytes) accepted");

    eval { $rsa->encrypt("x" x ($max_sha1 + 1)) };
    ok($@, "SHA-1 OAEP max+1 rejected");

    SKIP: {
        skip "Length validation with SHA-256 OAEP requires 3.x", 2 unless $is_3x;

        $rsa->use_sha256_oaep_hash();
        $ct = eval { $rsa->encrypt("x" x $max_sha256) };
        ok(!$@, "SHA-256 OAEP max ($max_sha256 bytes) accepted");

        eval { $rsa->encrypt("x" x ($max_sha256 + 1)) };
        ok($@, "SHA-256 OAEP max+1 rejected");
    }
}

# --- Pre-3.x: non-SHA1 OAEP croaks at encrypt time ---

SKIP: {
    skip "Only relevant on pre-3.x OpenSSL", 1 if $is_3x;

    $rsa->use_sha256_oaep_hash();
    eval { $rsa->encrypt($plaintext) };
    like($@, qr/OAEP with non-SHA1 hash requires OpenSSL 3\.0/,
         "non-SHA1 OAEP croaks on pre-3.x");
}

done_testing;
