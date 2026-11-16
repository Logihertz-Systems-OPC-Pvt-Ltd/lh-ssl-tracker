Name:           lh-ssl-tracker
Version:        0.1.0
Release:        1%{?dist}
Summary:        lh-ssl - X.509 Certificate Expiration Urgency & Cipher Strength
License:        Apache-2.0
URL:            https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-ssl-tracker
Source0:        %{name}-%{version}-src.tar.gz
Packager:       Sameer Tawade <ops@logihertz.com>
BuildArch:      noarch

%description
X.509 PKI certificate chain and TLS posture auditor monitoring certificate expiration windows, weak cipher suites, TLS 1.3 enforcement, OCSP stapling, CAA binding, and Certificate Transparency logs.

%prep
%autosetup -n %{name}-0.1.0

%build
# Industrial clean-room build with zero external runtime dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

if [ -f bin/lh-ssl ]; then
    install -m 0755 bin/lh-ssl %{buildroot}%{_bindir}/lh-ssl
elif [ -f lh-ssl ]; then
    install -m 0755 lh-ssl %{buildroot}%{_bindir}/lh-ssl
fi

install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 SPEC.md %{buildroot}%{_docdir}/%{name}/SPEC.md
install -m 0644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -m 0644 NOTICE %{buildroot}%{_docdir}/%{name}/NOTICE

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/SPEC.md
%doc %{_docdir}/%{name}/NOTICE
%license %{_docdir}/%{name}/LICENSE

%changelog
* Mon Nov 16 2026 Sameer Tawade <ops@logihertz.com> - 0.1.0-1
- Initial production release for Logihertz Systems Ecosystem and STRUCT OS.
