use strict;
use Test::More;

use Crypt::OpenSSL::Random;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Guess qw(openssl_version);

my ($major, $minor, $patch) = openssl_version;

BEGIN {
    plan tests => 87 + ( UNIVERSAL::can( "Crypt::OpenSSL::RSA", "use_sha512_hash" ) ? 4 * 5 : 0 );
}

sub _Test_Encrypt_And_Decrypt {
    my ( $p_plaintext_length, $p_rsa, $p_check_private_encrypt, $padding, $hash ) = @_;

    my ( $ciphertext, $decoded_text );
    my $plaintext = pack(
        "C${p_plaintext_length}",
        (
            1, 255, 0, 128, 4,    # Make sure these characters work
            map { int( rand 256 ) } ( 1 .. $p_plaintext_length - 5 )
        )
    );
    ok( $ciphertext   = $p_rsa->encrypt($plaintext), "Padding method $padding is valid for encrypting with $hash" );
    ok( $decoded_text = $p_rsa->decrypt($ciphertext), "Padding method $padding is valid for decrypting with $hash" );
    ok( $decoded_text eq $plaintext );

    if ($p_check_private_encrypt) {
        ok( $ciphertext   = $p_rsa->private_encrypt($plaintext), "Padding method $padding is valid for private_encrypt with $hash" );
        ok( $decoded_text = $p_rsa->public_decrypt($ciphertext), "Padding method $padding is valid for private_decrypt with $hash" );
        ok( $decoded_text eq $plaintext );
    }
}

sub _Test_Sign_And_Verify {
    my ( $p_plaintext_length, $rsa, $rsa_pub, $padding, $hash ) = @_;

    my $plaintext = pack(
        "C${p_plaintext_length}",
        (
            1, 255, 0, 128, 4,    # Make sure these characters work
            map { int( rand 256 ) } ( 1 .. $p_plaintext_length - 5 )
        )
    );

    my $sig = eval { $rsa->sign($plaintext) };

  SKIP: {
        skip "OpenSSL error: illegal or unsupported padding mode - $hash", 6 if $@ =~ /illegal or unsupported padding mode/i;
        skip "OpenSSL error: invalid digest - $hash", 6 if $@ =~ /invalid digest/i;
        ok(!$@, "Padding method $padding is valid for signing with $hash");
        ok( $rsa_pub->verify( $plaintext, $sig ), "Padding method $padding is valid for verifying with $hash");

        my $false_sig = unpack "H*", $sig;
        $false_sig =~ tr/[a-f]/[0a-d]/;
        ok( !$rsa_pub->verify( $plaintext, pack( "H*", $false_sig )), "rsa_pub: False signature does not verify");
        ok( !$rsa->verify( $plaintext, pack( "H*", $false_sig )), "rsa: False signature does not verify");

        my $sig_of_other = $rsa->sign("different");
        ok( !$rsa_pub->verify( $plaintext, $sig_of_other ), "rsa_pub: plaintext does not match signature" );
        ok( !$rsa->verify( $plaintext, $sig_of_other ), "rsa: plaintext does not match signature");
    }
}

Crypt::OpenSSL::Random::random_seed("OpenSSL needs at least 32 bytes.");
Crypt::OpenSSL::RSA->import_random_seed();

my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);
ok( $rsa->size() * 8 == 2048);
ok( $rsa->check_key() );

my $private_key_string = $rsa->get_private_key_string();
my $public_key_string  = $rsa->get_public_key_string();

ok( $private_key_string and $public_key_string );

my $plaintext = "The quick brown fox jumped over the lazy dog";
my $rsa_priv  = Crypt::OpenSSL::RSA->new_private_key($private_key_string);
ok( $plaintext eq $rsa_priv->decrypt( $rsa_priv->encrypt($plaintext) ) );

my $rsa_pub = Crypt::OpenSSL::RSA->new_public_key($public_key_string);

my @unsupported_paddings = qw/pkcs1 sslv23/;

$plaintext .= $plaintext x 5;
# pkcs1 sslv23 are unsupported methods
foreach my $pad (@unsupported_paddings) {
    my $method = "use_${pad}_padding";
    SKIP: {
        skip "OpenSSL version less than 3.0 supports sslv23", 1
            if $major lt '3.0' && $pad eq 'sslv23';
        eval {
            $rsa->$method;
        };
        ok($@, "Padding method $pad unsupported");
    }
}

my @supported_paddings = qw/no pkcs1_pss pkcs1_oaep/;
# no pkcs1_pss pkcs1_oaep are supported methods
foreach my $pad (@supported_paddings) {
    my $method = "use_${pad}_padding";
    eval {
        $rsa->$method;
    };
    ok(!$@, "Padding method $pad supported");
}

my @hashes = qw/md5 sha1 sha224 sha256 sha384 sha512 ripemd160/; # whirlpool/;

my %padding_methods = (
                       'no'          => {'sign' => 1, 'encrypt' => 1, 'pad' => 0},
                       'pkcs1_pss'   => {'sign' => 1, 'encrypt' => 0, 'pad' => 1},
                       'pkcs1_oaep'  => {'sign' => 0, 'encrypt' => 1, 'pad' => 42},
                       'pkcs1'       => {'sign' => 0, 'encrypt' => 0, 'pad' => 11},
                       #'sslv23'      => {'sign' => 0, 'encrypt' => 0, 'pad' => 11},
                    );


foreach my $padding (keys %padding_methods) {
    diag $padding;
    foreach my $hash (@hashes) {
        next if $hash ne 'sha256' && $padding eq 'x931';
        my $props = $padding_methods{$padding};
        my $sign = $props->{sign};
        my $encrypt = $props->{encrypt};
        my $pad = $props->{pad};

        my $hash_mth = "use_${hash}_hash";
        $rsa->$hash_mth;
        $rsa_pub->$hash_mth;
        my $method = "use_${padding}_padding";
        if ($sign || $encrypt ) {
            $rsa->$method;
            $rsa_pub->$method;
        }
        # Valid signing methods
        if ($sign && $pad) {
            _Test_Sign_And_Verify( $rsa->size() - $pad, $rsa, $rsa_pub, $padding, $hash );
        }

        # Invalid signing methods
        if ((!$sign) && $pad) {
            eval {
                $rsa->$method;
                $rsa->sign($plaintext);
            };
            ok(defined $@, "Padding $padding is invalid for signing");
        }

        # Valid encryption methods with padding
        if ($encrypt) {
           _Test_Encrypt_And_Decrypt( $rsa->size() - $pad, $rsa, 0, $padding, $hash );
        }

    }
}

# Try
