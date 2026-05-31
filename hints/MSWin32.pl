use Config;
use Crypt::OpenSSL::Guess 0.11 qw(openssl_lib_paths);
if (my $libs = `pkg-config --libs libcrypto 2>nul`) {
  # strawberry perl has pkg-config
  $self->{LIBS} = [openssl_lib_paths() . " $libs"];
}
else {
  $self->{LIBS} = [openssl_lib_paths() . '-llibeay32'] if $Config{cc} =~ /cl/; # msvc with ActivePerl
  $self->{LIBS} = [openssl_lib_paths() . '-leay32']    if $Config{gccversion}; # gcc
}
