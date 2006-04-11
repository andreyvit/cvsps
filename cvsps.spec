Version: 2.1
Summary: CVSps is a program for generating 'patchset' information from a CVS repository
Name: cvsps
Release: 1
URL: http://www.cobite.com/cvsps/
Source0: %{name}-%{version}.tar.gz
License: GPL
Group: Development/Tools
BuildRoot: %{_tmppath}/%{name}-root
prefix: /usr

%description 
CVSps is a program for generating 'patchset' information from a CVS
repository. A patchset in this case is defined as a set of changes
made to a collection of files, and all committed at the same time
(using a single 'cvs commit' command). This information is valuable to
seeing the big picture of the evolution of a cvs project. While cvs
tracks revision information, it is often difficult to see what changes
were committed 'atomically' to the repository.

%prep
%setup -q

%build
make

%install
rm -rf $RPM_BUILD_ROOT
%makeinstall

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc README CHANGELOG COPYING
%{prefix}/bin/cvsps
%{prefix}/man/man*/*

%changelog
* Tue Apr  1 2002 David Mansfield <cvsps@dm.cobite.com>
- (no really - not April fools joke)
- revise spec file from Jan
- merge Makefile changes
* Tue Mar  5 2002 Jan IVEN <jan.iven@cern.ch>
- Initial build.


