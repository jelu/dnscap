Summary: DNS traffic capture
Name: dnscap
Version: 0.1.10
Release: 0
License: GPL
Group: Networking/Utilities
URL: https://github.com/verisign/dnscap
Source0: dnscap-master.zip
Source1: dnscap.init
Packager: Francisco Monserrat <francisco.monserrat@rediris.es>
# Temporary location where the RPM will be built
BuildRoot: %{_tmppath}/%{name}-%{version}-build
Requires: libpcap 

%description

This program will capture the DNS traffic and store it in tcpdump libpcap format it has a lot of
options and features (see man page) to process the pages after it.
%prep

%setup -q -n dnscap-master

%build
PATH=/usr/bin:/bin:/usr/sbin:/sbin

if [ -x ./configure ]; then
  CFLAGS="$RPM_OPT_FLAGS" ./configure 
else
  CFLAGS="$RPM_OPT_FLAGS" ./autogen.sh 
fi
make
#

# Installation may be a matter of running an install make target or you
# may need to manually install files with the install command.
%install
PATH=/usr/bin:/bin:/usr/sbin:/sbin
# MAKEFILE lleva hardcodeado el install, lo hacemos nosotros make DESTDIR=$RPM_BUILD_ROOT install 
#
mkdir -p $RPM_BUILD_ROOT/usr/sbin/
mkdir -p $RPM_BUILD_ROOT/usr/share/man/man1/
mkdir -p $RPM_BUILD_ROOT/var/lib/dnscap/
mkdir -p $RPM_BUILD_ROOT/etc/init.d/
cp dnscap $RPM_BUILD_ROOT/usr/sbin/ 
cp dnscap.1 $RPM_BUILD_ROOT/usr/share/man/man1/
cp %{SOURCE1} $RPM_BUILD_ROOT/etc/init.d/dnscap

%clean
rm -fr $RPM_BUILD_ROOT

%files
/usr/sbin/dnscap
/usr/share/man/man1/dnscap.1.gz
/var/lib/dnscap
/etc/init.d/dnscap 

%doc CONTRIBUTORS LICENSE README.md 

%defattr(-, root, root)

%changelog
* Thu Apr 23 2015 Francisco Monserrat <francisco.monserrat@rediris.es>
- Initial Version


