Name:       nfc-plugin-emul
Summary:    NFC emul plugin
Version:    0.0.12
Release:    0
Group:      TO_BE/FILLED_IN
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(gobject-2.0)
BuildRequires: pkgconfig(vconf)
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(nfc-common-lib)
BuildRequires: cmake
BuildRequires: gettext-tools

%description
NFC Plugin Emul

%prep
%setup -q


%build
%cmake .


%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp -af LICENSE.APLv2 %{buildroot}/usr/share/license/%{name}

%make_install


%post -p /sbin/ldconfig


%postun -p /sbin/ldconfig


%files
%defattr(-,root,root,-)
%{_libdir}/*.so
/usr/share/license/%{name}