Name:       nfc-plugin-emul
Summary:    NFC emul plugin
Version:    0.0.2
Release:    2
Group:      TO_BE/FILLED_IN
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
BuildRequires: pkgconfig(aul)
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(gobject-2.0)
BuildRequires: pkgconfig(syspopup)
BuildRequires: pkgconfig(dbus-glib-1)
BuildRequires: pkgconfig(vconf)
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(tapi)
BuildRequires: pkgconfig(ecore)
BuildRequires: pkgconfig(elementary)
BuildRequires: pkgconfig(mm-common)
BuildRequires: pkgconfig(mm-sound)
BuildRequires: pkgconfig(security-server)
BuildRequires: pkgconfig(contacts-service)
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(memo)
BuildRequires: pkgconfig(nfc-common-lib)
BuildRequires: cmake
BuildRequires: gettext-tools

%description
NFC Plugin Emul

%prep
%setup -q


%build
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install


%postun
/sbin/ldconfig
rm -f build-stamp configure-stamp
cd cmake_tmp
rm -rf $(CMAKE_TMP_DIR)
rm -rf CMakeCache.txt
rm -rf CMakeFiles
rm -rf cmake_install.cmake
rm -rf Makefile
rm -rf install_manifest.txt
rm -rf *.so

%post



%files
%defattr(-,root,root,-)
%{_libdir}/*.so

