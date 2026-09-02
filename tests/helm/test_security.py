from __future__ import annotations

import unittest

from tests.helm.helpers import EXPECTED, documents, render


class HelmSecurityTests(unittest.TestCase):
    def test_every_profile_has_namespace_rbac_pod_and_network_guards(self) -> None:
        for profile in EXPECTED:
            with self.subTest(profile=profile):
                output = render(profile).decode("utf-8")
                self.assertIn("podSelector: {}", output)
                self.assertIn("- Ingress", output)
                self.assertIn("- Egress", output)
                self.assertNotIn("kind: ClusterRole", output)
                self.assertNotIn("kind: Secret", output)
                self.assertNotIn("type: LoadBalancer", output)
                self.assertNotIn("type: NodePort", output)
                self.assertNotIn('verbs: ["*"]', output)
                for document in documents(output.encode()):
                    if "kind: Deployment" not in document:
                        continue
                    for token in ("serviceAccountName: planeon-", "automountServiceAccountToken: false", "runAsNonRoot: true", "type: RuntimeDefault", "allowPrivilegeEscalation: false", "readOnlyRootFilesystem: true", 'drop: ["ALL"]', "requests:", "limits:", "@sha256:"):
                        self.assertIn(token, document)
                    for forbidden in ("privileged: true", "hostNetwork:", "hostPID:", "hostIPC:", "hostPath:", "hostPort:"):
                        self.assertNotIn(forbidden, document)

    def test_openshift_is_arbitrary_uid_compatible_without_scc_mutation(self) -> None:
        output = render("regulated-openshift").decode("utf-8")
        for forbidden in ("runAsUser:", "fsGroup:", "supplementalGroups:", "SecurityContextConstraints"):
            self.assertNotIn(forbidden, output)

    def test_airgap_and_bridge_do_not_embed_external_or_cloud_endpoints(self) -> None:
        for profile in ("air-gap", "bridge"):
            output = render(profile).decode("utf-8").lower()
            for forbidden in ("http://", "https://", "amazonaws", "googleapis", "azure", "externalname"):
                self.assertNotIn(forbidden, output)


if __name__ == "__main__":
    unittest.main()
