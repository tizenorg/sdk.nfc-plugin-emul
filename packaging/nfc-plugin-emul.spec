Name:       nfc-plugin-emul
Summary:    NFC Plugin for Emulator
Version:    0.0.1
Release:    1
Group:      emulator
License:    Apache-2.0
Source0:    nfc-plugin-emul-%{version}.tar.gz
Source1001: packaging/nfc-plugin-emul.manifest 
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
BuildRequires:  pkgconfig(aul)
BuildRequires:  pkgconfig(syspopup-caller)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(ecore-input)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(elementary)
BuildRequires:  pkgconfig(mm-common)
BuildRequires:  pkgconfig(security-server)
BuildRequires:  pkgconfig(contacts-service)
BuildRequires:  pkgconfig(contacts-service)
BuildRequires:  pkgconfig(bluetooth-api)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(memo)
BuildRequires:  pkgconfig(syspopup-caller)
BuildRequires:  pkgconfig(nfc-common-lib)
BuildRequires:  cmake


%description
NFC Plugin for Emulator.


%prep
%setup -q 

%build
cp %{SOURCE1001} .
cmake . -DCMAKE_INSTALL_PREFIX=/usr
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install


%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%manifest nfc-plugin-emul.manifest
%defattr(-,root,root,-)
%{_libdir}/*.so
