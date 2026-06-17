use strict;
use warnings;
use Test::More;
use MIME::Base64;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Guess qw(openssl_version);

use File::Temp qw(tempfile);

my ($major, $minor, $patch) = openssl_version();

BEGIN { plan tests => 49 }

# --- Generate a key pair for testing ---

my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);

# --- Extract PEM public keys ---

my $pkcs1_pem = $rsa->get_public_key_string();        # PKCS#1 (BEGIN RSA PUBLIC KEY)
my $x509_pem  = $rsa->get_public_key_x509_string();   # X.509 (BEGIN PUBLIC KEY)

# --- Convert PEM to DER by stripping headers and base64-decoding ---

sub pem_to_der {
    my ($pem) = @_;
    $pem =~ s/-----BEGIN [^-]+-----//;
    $pem =~ s/-----END [^-]+-----//;
    $pem =~ s/\s+//g;
    return decode_base64($pem);
}

my $pkcs1_der = pem_to_der($pkcs1_pem);
my $x509_der  = pem_to_der($x509_pem);

# Sanity check: DER data starts with ASN.1 SEQUENCE tag
is( ord(substr($pkcs1_der, 0, 1)), 0x30, "PKCS#1 DER starts with SEQUENCE tag" );
is( ord(substr($x509_der, 0, 1)),  0x30, "X.509 DER starts with SEQUENCE tag" );

# --- Load DER keys via new_public_key ---

my ($pub_from_x509_der, $pub_from_pkcs1_der);

ok( $pub_from_x509_der = Crypt::OpenSSL::RSA->new_public_key($x509_der),
    "new_public_key loads X.509 DER key" );

ok( $pub_from_pkcs1_der = Crypt::OpenSSL::RSA->new_public_key($pkcs1_der),
    "new_public_key loads PKCS#1 DER key" );

# --- Verify round-trip: DER-loaded keys produce the same PEM output ---

is( $pub_from_x509_der->get_public_key_x509_string(), $x509_pem,
    "X.509 DER key exports to same X.509 PEM" );

is( $pub_from_x509_der->get_public_key_string(), $pkcs1_pem,
    "X.509 DER key exports to same PKCS#1 PEM" );

is( $pub_from_pkcs1_der->get_public_key_x509_string(), $x509_pem,
    "PKCS#1 DER key exports to same X.509 PEM" );

is( $pub_from_pkcs1_der->get_public_key_string(), $pkcs1_pem,
    "PKCS#1 DER key exports to same PKCS#1 PEM" );

# --- Verify DER-loaded keys can actually verify signatures ---

$rsa->use_sha256_hash();
my $plaintext = "Hello, DER world!";
my $sig = $rsa->sign($plaintext);

$pub_from_x509_der->use_sha256_hash();
ok( $pub_from_x509_der->verify($plaintext, $sig),
    "X.509 DER-loaded key verifies signature" );

$pub_from_pkcs1_der->use_sha256_hash();
ok( $pub_from_pkcs1_der->verify($plaintext, $sig),
    "PKCS#1 DER-loaded key verifies signature" );

# --- Private key DER support ---

my $priv_pem = $rsa->get_private_key_string();
my $priv_der = pem_to_der($priv_pem);

is( ord(substr($priv_der, 0, 1)), 0x30, "Private key DER starts with SEQUENCE tag" );

my $priv_from_der;
ok( $priv_from_der = Crypt::OpenSSL::RSA->new_private_key($priv_der),
    "new_private_key loads DER-encoded private key" );

ok( $priv_from_der->is_private(),
    "DER-loaded private key is recognized as private" );

is( $priv_from_der->get_public_key_x509_string(), $x509_pem,
    "DER-loaded private key exports same public key" );

# Verify DER-loaded private key can sign and original public key can verify
$priv_from_der->use_sha256_hash();
my $sig2 = $priv_from_der->sign($plaintext);
ok( $pub_from_x509_der->verify($plaintext, $sig2),
    "signature from DER-loaded private key verifies" );

# Error: DER-like data for private key
eval { Crypt::OpenSSL::RSA->new_private_key("\x30\x00") };
ok( $@, "new_private_key croaks on truncated DER data" );

# Error: bogus binary data for private key
eval { Crypt::OpenSSL::RSA->new_private_key("\x01\x02\x03\x04") };
like( $@, qr/unrecognized key format/,
    "new_private_key gives helpful error on random binary data" );

# PEM private keys still work through the wrapper
my $priv_from_pem;
ok( $priv_from_pem = Crypt::OpenSSL::RSA->new_private_key($priv_pem),
    "new_private_key still loads PEM-encoded private key" );

# --- Error cases ---

# DER-like data that isn't a valid key (no RSA OID, so falls through to PKCS#1 path)
eval { Crypt::OpenSSL::RSA->new_public_key("\x30\x00") };
ok( $@, "new_public_key croaks on truncated DER data" );

# Completely bogus binary data (not starting with 0x30)
eval { Crypt::OpenSSL::RSA->new_public_key("\x01\x02\x03\x04") };
like( $@, qr/unrecognized key format/,
    "new_public_key gives helpful error on random binary data" );

# Empty string
eval { Crypt::OpenSSL::RSA->new_public_key("") };
like( $@, qr/unrecognized key format/,
    "new_public_key gives helpful error on empty string" );

# --- Encrypted PKCS#8 DER private key with passphrase ---

my $passphrase = 'test_der_pass';
my $enc_pkcs8_pem = $rsa->get_private_key_pkcs8_string($passphrase, 'aes-128-cbc');
my $enc_pkcs8_der = pem_to_der($enc_pkcs8_pem);

is( ord(substr($enc_pkcs8_der, 0, 1)), 0x30,
    "Encrypted PKCS#8 DER starts with SEQUENCE tag" );

my $priv_from_enc_der;
ok( $priv_from_enc_der = Crypt::OpenSSL::RSA->new_private_key($enc_pkcs8_der, $passphrase),
    "new_private_key loads encrypted PKCS#8 DER with passphrase" );

ok( $priv_from_enc_der->is_private(),
    "Encrypted PKCS#8 DER-loaded key is private" );

is( $priv_from_enc_der->get_public_key_x509_string(), $x509_pem,
    "Encrypted PKCS#8 DER key exports same public key as original" );

$priv_from_enc_der->use_sha256_hash();
my $sig3 = $priv_from_enc_der->sign($plaintext);
ok( $pub_from_x509_der->verify($plaintext, $sig3),
    "Signature from encrypted PKCS#8 DER-loaded key verifies" );

eval { Crypt::OpenSSL::RSA->new_private_key($enc_pkcs8_der, 'wrong_pass') };
ok( $@, "new_private_key croaks on wrong passphrase for encrypted PKCS#8 DER" );

# PEM header for wrong type
eval { Crypt::OpenSSL::RSA->new_public_key("-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----\n") };
like( $@, qr/unrecognized key format/,
    "new_public_key gives helpful error on certificate PEM" );

# --- Non-RSA DER key rejection ---
# On OpenSSL 3.x, d2i_PUBKEY_bio() accepts any key type.
# _new_public_key_x509_der must reject non-RSA keys.

SKIP: {
    my $ec_pem = `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 2>/dev/null`;
    skip "EC key generation not available", 2
        unless ($? >> 8) == 0 && $ec_pem =~ /-----BEGIN PRIVATE KEY-----/;

    my ($tmpfh, $tmpfile) = tempfile(UNLINK => 1);
    print $tmpfh $ec_pem;
    close $tmpfh;
    my $ec_pub_pem = `openssl pkey -in $tmpfile -pubout -outform PEM 2>/dev/null`;
    skip "EC public key export failed", 2
        unless ($? >> 8) == 0 && $ec_pub_pem =~ /-----BEGIN PUBLIC KEY-----/;

    my $ec_pub_der = pem_to_der($ec_pub_pem);
    eval { Crypt::OpenSSL::RSA->_new_public_key_x509_der($ec_pub_der) };
    ok($@, "_new_public_key_x509_der rejects EC DER key");
    like($@, qr/not an RSA key|ASN1|expecting an rsa key/i,
        "_new_public_key_x509_der gives appropriate error for non-RSA DER key");
}

# --- DER export tests ---

# PKCS#1 public key DER export
my $pub_pkcs1_der_export = $rsa->get_public_key_der_string();
is( ord(substr($pub_pkcs1_der_export, 0, 1)), 0x30,
    "get_public_key_der_string starts with SEQUENCE tag" );
is( $pub_pkcs1_der_export, $pkcs1_der,
    "get_public_key_der_string matches pem_to_der of PEM export" );

my $pub_from_pkcs1_der_export = Crypt::OpenSSL::RSA->new_public_key($pub_pkcs1_der_export);
$pub_from_pkcs1_der_export->use_sha256_hash();
ok( $pub_from_pkcs1_der_export->verify($plaintext, $sig),
    "PKCS#1 DER export round-trips and verifies" );

# Alias test
is( $rsa->get_public_key_pkcs1_der_string(), $pub_pkcs1_der_export,
    "get_public_key_pkcs1_der_string is alias for get_public_key_der_string" );

# X.509 public key DER export
my $pub_x509_der_export = $rsa->get_public_key_x509_der_string();
is( ord(substr($pub_x509_der_export, 0, 1)), 0x30,
    "get_public_key_x509_der_string starts with SEQUENCE tag" );
is( $pub_x509_der_export, $x509_der,
    "get_public_key_x509_der_string matches pem_to_der of PEM export" );

my $pub_from_x509_der_export = Crypt::OpenSSL::RSA->new_public_key($pub_x509_der_export);
$pub_from_x509_der_export->use_sha256_hash();
ok( $pub_from_x509_der_export->verify($plaintext, $sig),
    "X.509 DER export round-trips and verifies" );

# PKCS#1 private key DER export
my $priv_pkcs1_der_export = $rsa->get_private_key_der_string();
is( ord(substr($priv_pkcs1_der_export, 0, 1)), 0x30,
    "get_private_key_der_string starts with SEQUENCE tag" );
is( $priv_pkcs1_der_export, $priv_der,
    "get_private_key_der_string matches pem_to_der of PEM export" );

my $priv_from_der_export = Crypt::OpenSSL::RSA->new_private_key($priv_pkcs1_der_export);
ok( $priv_from_der_export->is_private(),
    "PKCS#1 DER export round-trips as private key" );
$priv_from_der_export->use_sha256_hash();
my $sig_from_der_export = $priv_from_der_export->sign($plaintext);
ok( $pub_from_x509_der->verify($plaintext, $sig_from_der_export),
    "signature from PKCS#1 DER-exported private key verifies" );

# Unencrypted PKCS#8 private key DER export
my $pkcs8_pem = $rsa->get_private_key_pkcs8_string();
my $pkcs8_der_expected = pem_to_der($pkcs8_pem);
my $pkcs8_der_export = $rsa->get_private_key_pkcs8_der_string();
is( ord(substr($pkcs8_der_export, 0, 1)), 0x30,
    "get_private_key_pkcs8_der_string starts with SEQUENCE tag" );
is( $pkcs8_der_export, $pkcs8_der_expected,
    "get_private_key_pkcs8_der_string matches pem_to_der of PEM export" );

SKIP: {
    skip "Unencrypted PKCS#8 DER import requires OpenSSL 3.x", 1
        if $major < 3 || !defined $patch;
    my $priv_from_pkcs8_der_export = Crypt::OpenSSL::RSA->new_private_key($pkcs8_der_export);
    ok( $priv_from_pkcs8_der_export->is_private(),
        "PKCS#8 DER export round-trips as private key" );
}

# Encrypted PKCS#8 DER export
my $der_pass = 'test_export_pass';
my $enc_pkcs8_der_export = $rsa->get_private_key_pkcs8_der_string($der_pass, 'aes-128-cbc');
is( ord(substr($enc_pkcs8_der_export, 0, 1)), 0x30,
    "encrypted PKCS#8 DER export starts with SEQUENCE tag" );
my $priv_from_enc_pkcs8_der = Crypt::OpenSSL::RSA->new_private_key($enc_pkcs8_der_export, $der_pass);
ok( $priv_from_enc_pkcs8_der->is_private(),
    "encrypted PKCS#8 DER export round-trips with passphrase" );

eval { Crypt::OpenSSL::RSA->new_private_key($enc_pkcs8_der_export, 'wrong') };
ok( $@, "encrypted PKCS#8 DER export rejects wrong passphrase" );

# Error: public key cannot export private DER
my $pub_only = Crypt::OpenSSL::RSA->new_public_key($x509_pem);
eval { $pub_only->get_private_key_der_string() };
like( $@, qr/Public keys cannot/,
    "get_private_key_der_string croaks on public-only key" );

eval { $pub_only->get_private_key_pkcs8_der_string() };
like( $@, qr/Public keys cannot/,
    "get_private_key_pkcs8_der_string croaks on public-only key" );
