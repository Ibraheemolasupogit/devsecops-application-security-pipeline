"""Offline invariants for the Kustomize-rendered Kubernetes workloads."""

from __future__ import annotations

import re
from typing import Any

import pytest
from scripts.kubernetes_workload import documents, render

ENVIRONMENTS = {"qa": "qa", "prod": "production"}


@pytest.fixture(scope="module")
def rendered() -> dict[str, tuple[str, list[dict[str, Any]]]]:
    return {
        environment: (
            text := render(environment),
            documents(text),
        )
        for environment in ENVIRONMENTS
    }


def by_kind(resources: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [resource for resource in resources if resource["kind"] == kind]


def one(resources: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    matches = by_kind(resources, kind)
    assert len(matches) == 1, f"expected one {kind}, got {len(matches)}"
    return matches[0]


def deployment(resources: list[dict[str, Any]]) -> dict[str, Any]:
    return one(resources, "Deployment")


def pod_spec(resources: list[dict[str, Any]]) -> dict[str, Any]:
    value: object = deployment(resources)["spec"]["template"]["spec"]
    assert isinstance(value, dict)
    return value


def api_container(resources: list[dict[str, Any]]) -> dict[str, Any]:
    value: object = pod_spec(resources)["containers"][0]
    assert isinstance(value, dict)
    return value


def test_environment_namespace_and_pod_security_admission(
    rendered: dict[str, tuple[str, list[dict[str, Any]]]],
) -> None:
    for environment, namespace in ENVIRONMENTS.items():
        resources = rendered[environment][1]
        namespace_object = one(resources, "Namespace")
        assert namespace_object["metadata"]["name"] == namespace
        labels = namespace_object["metadata"]["labels"]
        assert labels["platform.example.com/environment"] == namespace
        assert labels["pod-security.kubernetes.io/enforce"] == "restricted"
        assert labels["pod-security.kubernetes.io/enforce-version"] == "v1.36"
        assert all(
            resource["metadata"].get("namespace") == namespace
            for resource in resources
            if resource["kind"] != "Namespace"
        )
        assert deployment(resources)["metadata"]["namespace"] == namespace
    assert ENVIRONMENTS["qa"] != ENVIRONMENTS["prod"]


def test_one_immutable_image_contract_is_shared_between_environments(
    rendered: dict[str, tuple[str, list[dict[str, Any]]]],
) -> None:
    images = {api_container(resources)["image"] for _, resources in rendered.values()}
    assert len(images) == 1
    image = images.pop()
    assert "@sha256:" in image
    assert ":latest" not in image
    assert re.fullmatch(
        r"<ACCOUNT>\.dkr\.ecr\.<REGION>\.amazonaws\.com/"
        r"genomic-research-access-api@sha256:<DIGEST>",
        image,
    )


def test_pod_and_container_security_contexts_are_restricted(
    rendered: dict[str, tuple[str, list[dict[str, Any]]]],
) -> None:
    for _, resources in rendered.values():
        spec = pod_spec(resources)
        pod_security = spec["securityContext"]
        assert pod_security["runAsNonRoot"] is True
        assert pod_security["runAsUser"] == 10001
        assert pod_security["runAsGroup"] == 10001
        assert pod_security["seccompProfile"]["type"] == "RuntimeDefault"
        assert spec["hostNetwork"] is False
        assert spec["hostPID"] is False
        assert spec["hostIPC"] is False

        container = api_container(resources)
        security = container["securityContext"]
        assert security["runAsNonRoot"] is True
        assert security["runAsUser"] == 10001
        assert security["runAsGroup"] == 10001
        assert security["allowPrivilegeEscalation"] is False
        assert security["privileged"] is False
        assert security["readOnlyRootFilesystem"] is True
        assert security["capabilities"]["drop"] == ["ALL"]
        assert "add" not in security["capabilities"]


def test_service_account_has_no_api_token_or_rbac(
    rendered: dict[str, tuple[str, list[dict[str, Any]]]],
) -> None:
    for _, resources in rendered.values():
        service_account = one(resources, "ServiceAccount")
        assert service_account["automountServiceAccountToken"] is False
        assert pod_spec(resources)["automountServiceAccountToken"] is False
        assert pod_spec(resources)["serviceAccountName"] == service_account["metadata"]["name"]
        assert not by_kind(resources, "Role")
        assert not by_kind(resources, "RoleBinding")
        assert not by_kind(resources, "ClusterRole")
        assert not by_kind(resources, "ClusterRoleBinding")


def test_service_is_cluster_internal_only(
    rendered: dict[str, tuple[str, list[dict[str, Any]]]],
) -> None:
    for _, resources in rendered.values():
        service = one(resources, "Service")
        assert service["spec"]["type"] == "ClusterIP"
        assert service["spec"]["ports"] == [
            {"name": "http", "port": 8000, "targetPort": "http", "protocol": "TCP"}
        ]
        assert not by_kind(resources, "Ingress")


def test_real_health_route_drives_startup_readiness_and_liveness(
    rendered: dict[str, tuple[str, list[dict[str, Any]]]],
) -> None:
    for _, resources in rendered.values():
        container = api_container(resources)
        assert container["ports"] == [{"name": "http", "containerPort": 8000, "protocol": "TCP"}]
        for name in ("startupProbe", "readinessProbe", "livenessProbe"):
            assert container[name]["httpGet"] == {"path": "/health", "port": "http"}
        assert pod_spec(resources)["terminationGracePeriodSeconds"] == 30
        strategy = deployment(resources)["spec"]["strategy"]
        assert strategy["type"] == "RollingUpdate"
        assert strategy["rollingUpdate"] == {"maxUnavailable": 0, "maxSurge": 1}


def test_environment_replica_resources_and_disruption_budgets_are_consistent(
    rendered: dict[str, tuple[str, list[dict[str, Any]]]],
) -> None:
    for environment, (_, resources) in rendered.items():
        replicas = deployment(resources)["spec"]["replicas"]
        expected_replicas = 1 if environment == "qa" else 2
        assert replicas == expected_replicas
        assert deployment(resources)["spec"]["revisionHistoryLimit"] == 5
        container = api_container(resources)
        assert container["resources"]["requests"]
        assert container["resources"]["limits"]
        assert one(resources, "ResourceQuota")["spec"]["hard"]["pods"]
        assert one(resources, "LimitRange")["spec"]["limits"]
        pdb = one(resources, "PodDisruptionBudget")
        assert pdb["spec"]["maxUnavailable"] == 1
        if environment == "prod":
            assert replicas - pdb["spec"]["maxUnavailable"] >= 1
        else:
            assert pdb["spec"]["maxUnavailable"] <= replicas


def test_network_policy_limits_ingress_and_allows_only_dns_egress(
    rendered: dict[str, tuple[str, list[dict[str, Any]]]],
) -> None:
    for _, resources in rendered.values():
        policy = one(resources, "NetworkPolicy")["spec"]
        assert set(policy["policyTypes"]) == {"Ingress", "Egress"}
        ingress_peer = policy["ingress"][0]["from"][0]
        assert (
            ingress_peer["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
            == "ingress-system"
        )
        assert (
            ingress_peer["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
            == "workload-proxy"
        )
        egress_rule = policy["egress"][0]
        assert (
            egress_rule["to"][0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
            == "kube-system"
        )
        assert {port["port"] for port in egress_rule["ports"]} == {53}
        assert {port["protocol"] for port in egress_rule["ports"]} == {"TCP", "UDP"}


def test_configuration_is_non_sensitive_and_secret_is_external(
    rendered: dict[str, tuple[str, list[dict[str, Any]]]],
) -> None:
    for environment, (text, resources) in rendered.items():
        config = one(resources, "ConfigMap")
        data = config["data"]
        assert config["immutable"] is True
        assert data["GRAA_ENVIRONMENT"] == ENVIRONMENTS[environment]
        assert data["GRAA_EXPOSE_API_DOCS"] == "false"
        assert data["GRAA_JWT_ISSUER"].startswith("https://issuer.invalid/")
        assert data["GRAA_JWT_PUBLIC_KEY_PATH"] == ("/var/run/api-identity/jwt_public_key.pem")
        assert not by_kind(resources, "Secret")
        assert api_container(resources)["volumeMounts"][0]["readOnly"] is True
        secret_volumes = [volume for volume in pod_spec(resources)["volumes"] if "secret" in volume]
        assert len(secret_volumes) == 1
        assert secret_volumes[0]["secret"]["secretName"] == "api-identity"
        assert "-----BEGIN PRIVATE KEY-----" not in text
        assert "AKIA" not in text
        assert "REPLACE_WITH_SECRET" not in text


def test_overlays_preserve_common_workload_security_and_service_contract(
    rendered: dict[str, tuple[str, list[dict[str, Any]]]],
) -> None:
    qa = rendered["qa"][1]
    prod = rendered["prod"][1]
    for kind in ("Service", "NetworkPolicy", "PodDisruptionBudget"):
        assert one(qa, kind)["spec"] == one(prod, kind)["spec"]
    assert one(qa, "ServiceAccount")["automountServiceAccountToken"] is False
    assert one(prod, "ServiceAccount")["automountServiceAccountToken"] is False
    assert api_container(qa)["securityContext"] == api_container(prod)["securityContext"]
    assert pod_spec(qa)["securityContext"] == pod_spec(prod)["securityContext"]
    assert api_container(qa)["ports"] == api_container(prod)["ports"]
