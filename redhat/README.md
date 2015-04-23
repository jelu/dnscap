# RedHAT/Centos/... RPM package

## What is provided

1. A rpm SPEC file to build a rpm package compatible with Redhat/Centos and other RPM based distrubutions
1. init.d launch for launch the daemon on boot

## How to build the package

To create a RedHat/CentOS RPM package you can use this provided files:

1. Setup the normal procedure to create a build environment, for example http://wiki.centos.org/HowTos/SetupRpmBuildEnvironment
1. copy dnscap.spec to the ~/rpm/SPEC directory
1. copy dnscap.init t the ~/rpm/SOURCES directory.
1. download the files from git and put the zip file also in ~/rpm/SOURCES
1. change the pathnames, and so on if needed in the SPEC file
1. build the package with  ```$ rpmbuild -ba ~/rpm/SPEC/dnscap.spec´´´
1. install/distribute the package
1. if you need to modify the configuration of the capture daemon create the file /etc/sysconfig/dnscap as needed
1. launch the daemon

