import importlib.util
import ssl
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vpn_app import certificate_diagnostics, privileged_validation


ROOT = Path(__file__).resolve().parents[1]
VALID_DATES = ("Jan  1 00:00:00 2020 GMT", "Jan  1 00:00:00 2100 GMT")


class CertificateDiagnosticTests(unittest.TestCase):
    @staticmethod
    def _decoded(
        fingerprint="a" * 64,
        san=("DNS:gateway.example",),
        dates=VALID_DATES,
        hostname_match: bool | None = True,
    ):
        return (
            "CN=gateway.example",
            san,
            "CN=Example CA",
            dates[0],
            dates[1],
            fingerprint,
            hostname_match,
        )

    @staticmethod
    def _observation(
        ca_valid: bool | None = True,
        hostname: str = "gateway.example",
        port: int = 443,
    ):
        return certificate_diagnostics.TLSObservation(
            hostname=hostname,
            port=port,
            certificate_der=b"der-a",
            ca_valid=ca_valid,
            ca_error="unknown issuer" if ca_valid is False else "",
        )

    def _diagnose(self, *, ca_valid=True, fingerprint="a" * 64, **kwargs):
        with mock.patch.object(
            certificate_diagnostics,
            "_observe_tls",
            return_value=self._observation(ca_valid),
        ), mock.patch.object(
            certificate_diagnostics,
            "_decode_certificate",
            return_value=self._decoded(fingerprint=fingerprint),
        ), mock.patch.object(
            certificate_diagnostics,
            "_supported_client_version",
            return_value="1.21.0",
        ):
            return certificate_diagnostics.diagnose(
                "gateway.example",
                443,
                kwargs.pop("configured_fingerprint", "a" * 64),
                kwargs.pop("policy", "legacy-pinned"),
                **kwargs,
            )

    def test_certificate_rules_match_isolated_privileged_components(self):
        spec = importlib.util.spec_from_file_location(
            "vpn_openfortivpn_certificate_rules",
            ROOT / "vpn-openfortivpn.py",
        )
        self.assertIsNotNone(spec)
        assert spec is not None and spec.loader is not None
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)

        expected_policies = {
            "legacy-pinned",
            "system-ca",
            "system-ca-with-pinned-fallback",
        }
        self.assertEqual(privileged_validation.CERTIFICATE_POLICIES, expected_policies)
        self.assertEqual(launcher.CERTIFICATE_POLICIES, expected_policies)
        self.assertEqual(certificate_diagnostics._POLICIES, expected_policies)

        fingerprint_rules = (
            launcher.FINGERPRINT_RE,
            privileged_validation.FINGERPRINT_RE,
            certificate_diagnostics._FINGERPRINT_RE,
        )
        self.assertEqual(
            {(rule.pattern, rule.flags) for rule in fingerprint_rules},
            {(r"^[0-9a-fA-F]{64}$", fingerprint_rules[0].flags)},
        )

    def test_openssl_observation_matches_virtual_endpoint_without_sni(self):
        completed = subprocess.CompletedProcess(
            [],
            0,
            stdout=(
                b"-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"
                b"Verify return code: 0 (ok)\n"
            ),
            stderr=b"",
        )
        with mock.patch.object(
            certificate_diagnostics.subprocess,
            "run",
            return_value=completed,
        ) as run, mock.patch.object(
            certificate_diagnostics.ssl,
            "PEM_cert_to_DER_cert",
            return_value=b"same-observation",
        ):
            observation = certificate_diagnostics._observe_tls(
                "Original.Gateway.example",
                10443,
                2.0,
            )

        run.assert_called_once()
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("-connect") + 1], "Original.Gateway.example:10443")
        self.assertIn("-4", command)
        self.assertIn("-noservername", command)
        self.assertNotIn("-servername", command)
        self.assertEqual(observation.certificate_der, b"same-observation")
        self.assertTrue(observation.ca_valid)

    def test_only_confirmed_client_version_enables_tls_equivalence(self):
        with mock.patch.object(
            certificate_diagnostics.shutil,
            "which",
            return_value="/usr/bin/openfortivpn",
        ), mock.patch.object(
            certificate_diagnostics.subprocess,
            "run",
            side_effect=(
                subprocess.CompletedProcess([], 0, stdout="1.21.0\n", stderr=""),
                subprocess.CompletedProcess([], 0, stdout="1.22.0\n", stderr=""),
            ),
        ):
            self.assertEqual(
                certificate_diagnostics._supported_client_version(),
                "1.21.0",
            )
            self.assertIsNone(certificate_diagnostics._supported_client_version())

    @staticmethod
    def _generated_certificate_der(common_name: str, san: str | None = None) -> bytes:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate = root / "certificate.pem"
            command = [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                f"/CN={common_name}",
                "-keyout",
                str(root / "key.pem"),
                "-out",
                str(certificate),
            ]
            if san is not None:
                command.extend(["-addext", f"subjectAltName=DNS:{san}"])
            subprocess.run(command, capture_output=True, check=True)
            return ssl.PEM_cert_to_DER_cert(certificate.read_text(encoding="ascii"))

    def test_hostname_check_uses_san_and_cn_fallback_like_client(self):
        cases = (
            ("valid-san", "other.example", "gateway.example", True),
            ("cn-fallback", "gateway.example", None, True),
            ("divergent-san", "gateway.example", "other.example", False),
        )
        for name, common_name, san, expected in cases:
            with self.subTest(name=name):
                decoded = certificate_diagnostics._decode_certificate(
                    self._generated_certificate_der(common_name, san),
                    "gateway.example",
                )
                self.assertIs(decoded[-1], expected)

    def test_openssl_observation_keeps_ca_error_with_the_same_certificate(self):
        completed = subprocess.CompletedProcess(
            [],
            1,
            stdout=b"-----BEGIN CERTIFICATE-----\nleaf-a\n-----END CERTIFICATE-----\n",
            stderr=b"verify error:num=20:unable to get local issuer certificate\n",
        )
        with mock.patch.object(
            certificate_diagnostics.subprocess,
            "run",
            return_value=completed,
        ) as run, mock.patch.object(
            certificate_diagnostics.ssl,
            "PEM_cert_to_DER_cert",
            return_value=b"certificate-a",
        ):
            observation = certificate_diagnostics._observe_tls(
                "gateway.example",
                443,
                2.0,
            )

        run.assert_called_once()
        self.assertEqual(observation.certificate_der, b"certificate-a")
        self.assertFalse(observation.ca_valid)
        self.assertEqual(
            observation.ca_error,
            "unable to get local issuer certificate",
        )

    def test_different_endpoints_never_validate_a_pinned_fallback(self):
        observation_b = self._observation(
            ca_valid=False,
            hostname="endpoint-b.example",
        )
        with mock.patch.object(
            certificate_diagnostics,
            "_observe_tls",
            return_value=observation_b,
        ), mock.patch.object(
            certificate_diagnostics,
            "_supported_client_version",
            return_value="1.21.0",
        ), mock.patch.object(
            certificate_diagnostics,
            "_decode_certificate",
        ) as decode:
            result = certificate_diagnostics.diagnose(
                "gateway.example",
                443,
                "a" * 64,
                "system-ca-with-pinned-fallback",
            )

        decode.assert_not_called()
        self.assertEqual(result.severity, "WARNING")
        self.assertEqual(result.indeterminate_count, 1)
        self.assertFalse(result.fallback_used)

    def test_policy_matrix_uses_one_correlated_conclusion(self):
        cases = (
            ("system-ca", "", True, "a" * 64, "OK", False),
            ("system-ca", "", False, "a" * 64, "CRITICAL", False),
            ("legacy-pinned", "a" * 64, True, "a" * 64, "OK", False),
            ("legacy-pinned", "a" * 64, False, "a" * 64, "WARNING", True),
            (
                "system-ca-with-pinned-fallback",
                "a" * 64,
                True,
                "a" * 64,
                "OK",
                False,
            ),
            (
                "system-ca-with-pinned-fallback",
                "a" * 64,
                False,
                "a" * 64,
                "WARNING",
                True,
            ),
            ("legacy-pinned", "a" * 64, True, "b" * 64, "WARNING", False),
            ("legacy-pinned", "a" * 64, False, "b" * 64, "CRITICAL", False),
            (
                "system-ca-with-pinned-fallback",
                "a" * 64,
                True,
                "b" * 64,
                "WARNING",
                False,
            ),
            (
                "system-ca-with-pinned-fallback",
                "a" * 64,
                False,
                "b" * 64,
                "CRITICAL",
                False,
            ),
        )
        for policy, configured, ca_valid, observed, severity, fallback in cases:
            with self.subTest(policy=policy, ca_valid=ca_valid, observed=observed[0]):
                result = self._diagnose(
                    policy=policy,
                    configured_fingerprint=configured,
                    ca_valid=ca_valid,
                    fingerprint=observed,
                )
                self.assertEqual(result.severity, severity)
                self.assertEqual(result.fallback_used, fallback)
                self.assertEqual(
                    result.ok_count + result.warning_count + result.critical_count,
                    1,
                )

    def test_missing_invalid_or_prohibited_pin_is_critical_configuration(self):
        cases = (
            ("legacy-pinned", ""),
            ("legacy-pinned", "z" * 64),
            ("system-ca-with-pinned-fallback", "a" * 63),
            ("system-ca", "a" * 64),
        )
        with mock.patch.object(certificate_diagnostics, "_observe_tls") as observe:
            for policy, fingerprint in cases:
                with self.subTest(policy=policy, fingerprint_length=len(fingerprint)):
                    result = certificate_diagnostics.diagnose(
                        "gateway.example",
                        443,
                        fingerprint,
                        policy,
                    )
                    self.assertEqual(result.severity, "CRITICAL")
                    self.assertEqual(result.critical_count, 1)
            observe.assert_not_called()

    def test_collection_or_correlation_unavailable_is_warning_indeterminate(self):
        with mock.patch.object(
            certificate_diagnostics,
            "_observe_tls",
            side_effect=OSError("secret\npassword=hidden"),
        ), mock.patch.object(
            certificate_diagnostics,
            "_supported_client_version",
            return_value="1.21.0",
        ):
            result = certificate_diagnostics.diagnose(
                "gateway.example",
                443,
                "a" * 64,
                "legacy-pinned",
            )
        rendered = certificate_diagnostics.format_diagnostic(result)
        self.assertEqual(result.severity, "WARNING")
        self.assertEqual(result.indeterminate_count, 1)
        self.assertIn("password=[redacted]", rendered)
        self.assertNotIn("hidden", rendered)

        unverifiable = self._observation(ca_valid=None)
        with mock.patch.object(
            certificate_diagnostics,
            "_observe_tls",
            return_value=unverifiable,
        ), mock.patch.object(
            certificate_diagnostics,
            "_supported_client_version",
            return_value="1.21.0",
        ), mock.patch.object(certificate_diagnostics, "_decode_certificate") as decode:
            result = certificate_diagnostics.diagnose(
                "gateway.example",
                443,
                "a" * 64,
                "legacy-pinned",
            )
        decode.assert_not_called()
        self.assertEqual(result.severity, "WARNING")
        self.assertEqual(result.indeterminate_count, 1)

    def test_unknown_client_or_hostname_equivalence_never_reports_ok(self):
        with mock.patch.object(
            certificate_diagnostics,
            "_supported_client_version",
            return_value=None,
        ), mock.patch.object(certificate_diagnostics, "_observe_tls") as observe:
            unknown_client = certificate_diagnostics.diagnose(
                "gateway.example",
                443,
                "a" * 64,
                "legacy-pinned",
            )

        observe.assert_not_called()
        self.assertEqual(unknown_client.severity, "WARNING")
        self.assertEqual(unknown_client.indeterminate_count, 1)
        self.assertFalse(unknown_client.fallback_used)

        with mock.patch.object(
            certificate_diagnostics,
            "_supported_client_version",
            return_value="1.21.0",
        ), mock.patch.object(
            certificate_diagnostics,
            "_observe_tls",
            return_value=self._observation(True),
        ), mock.patch.object(
            certificate_diagnostics,
            "_decode_certificate",
            return_value=self._decoded(hostname_match=None),
        ):
            unknown_hostname = certificate_diagnostics.diagnose(
                "gateway.example",
                443,
                "a" * 64,
                "legacy-pinned",
            )

        self.assertEqual(unknown_hostname.severity, "WARNING")
        self.assertEqual(unknown_hostname.hostname_status, "Indeterminado")
        self.assertEqual(unknown_hostname.indeterminate_count, 1)
        self.assertFalse(unknown_hostname.fallback_used)
        self.assertEqual(unknown_hostname.ok_count, 0)

    def test_hostname_and_validity_are_part_of_classic_validation(self):
        decoded = self._decoded(
            san=("DNS:other.example",),
            dates=("Jan  1 00:00:00 2020 GMT", "Jan  1 00:00:00 2021 GMT"),
            hostname_match=False,
        )
        with mock.patch.object(
            certificate_diagnostics,
            "_observe_tls",
            return_value=self._observation(True),
        ), mock.patch.object(
            certificate_diagnostics,
            "_supported_client_version",
            return_value="1.21.0",
        ), mock.patch.object(
            certificate_diagnostics,
            "_decode_certificate",
            return_value=decoded,
        ):
            strict = certificate_diagnostics.diagnose(
                "gateway.example", 443, "", "system-ca"
            )
            pinned = certificate_diagnostics.diagnose(
                "gateway.example", 443, "a" * 64, "legacy-pinned"
            )
        self.assertEqual(strict.severity, "CRITICAL")
        self.assertEqual(pinned.severity, "WARNING")
        self.assertTrue(pinned.fallback_used)
        self.assertEqual(strict.hostname_status, "Inválido")
        self.assertEqual(strict.validity_status, "Expirada")

    def test_ca_error_classification_is_explicit(self):
        self.assertEqual(
            certificate_diagnostics._classify_ca_error(
                "unable to get local issuer certificate"
            ),
            "Cadeia incompleta ou CA ausente",
        )
        self.assertEqual(
            certificate_diagnostics._classify_ca_error("certificate has expired"),
            "Certificado da cadeia expirado ou ainda não válido",
        )


if __name__ == "__main__":
    unittest.main()
