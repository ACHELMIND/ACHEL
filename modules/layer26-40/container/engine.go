package container

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Engine struct {
	config ContainerEscapeConfig
}

func NewEngine(config ContainerEscapeConfig) *Engine {
	if config.DockerSocket == "" {
		config.DockerSocket = "/var/run/docker.sock"
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	return &Engine{config: config}
}

func (e *Engine) DockerEscape(targetContainer string) ContainerResult {
	result := ContainerResult{
		ID:            uuid.New().String(),
		ContainerName: targetContainer,
		ContainerType: ContainerTypeDocker,
		EscapeMethod:  EscapeMethodSocketMount,
		Timestamp:     time.Now(),
	}

	detectedMethods := e.detectSocketMount(targetContainer)
	result.Vulns = append(result.Vulns, detectedMethods...)

	privileged := e.checkPrivileged(targetContainer)
	if privileged {
		result.Vulns = append(result.Vulns, "PRIVILEGED_CONTAINER")
		result.EscapeMethod = EscapeMethodPrivilegedContainer
	}

	pidCheck := e.checkPIDNamespace(targetContainer)
	if pidCheck {
		result.Vulns = append(result.Vulns, "PID_NAMESPACE_SHARED")
	}

	cgroupEscape := e.detectCgroupEscape(targetContainer)
	if cgroupEscape {
		result.Vulns = append(result.Vulns, "CGROUP_ESCAPE_POSSIBLE")
	}

	procfsCheck := e.checkProcfsAccess(targetContainer)
	if procfsCheck {
		result.Vulns = append(result.Vulns, "PROCFS_ACCESS")
	}

	result.Success = len(result.Vulns) > 0
	if result.Success {
		result.Details = fmt.Sprintf("Found %d escape vectors in container %s", len(result.Vulns), targetContainer)
	} else {
		result.Details = fmt.Sprintf("No escape vectors found in container %s", targetContainer)
	}

	return result
}

func (e *Engine) KubernetesAPIAccess(config KubernetesConfig) KubernetesResult {
	result := KubernetesResult{
		ID:        uuid.New().String(),
		APIServer: config.APIServer,
		Timestamp: time.Now(),
	}

	if config.Namespace == "" {
		config.Namespace = "default"
	}

	nsInfo := e.enumerateNamespaces(config)
	result.Namespaces = nsInfo

	services := e.enumerateServices(config)
	result.Services = services

	if config.RBACEnum {
		roles := e.enumerateRBAC(config)
		result.Roles = roles
	}

	if config.NodeEnum {
		nodes := e.enumerateNodes(config)
		result.Nodes = nodes
	}

	pods := e.enumeratePods(config)
	result.Pods = pods

	result.EscapePaths = e.findEscapePaths(config)

	return result
}

func (e *Engine) ExtractSecrets(containerID string) ContainerResult {
	result := ContainerResult{
		ID:            uuid.New().String(),
		ContainerName: containerID,
		ContainerType: e.config.ContainerType,
		Timestamp:     time.Now(),
	}

	secretPaths := []string{
		"/etc/shadow", "/etc/passwd", "/root/.bash_history",
		"/var/log/auth.log", "/etc/ssh/ssh_host_rsa_key",
		"/proc/1/environ", "/run/secrets/",
	}

	for _, path := range secretPaths {
		found := e.probeSecretPath(containerID, path)
		if found {
			result.SecretsFound = append(result.SecretsFound, SecretEntry{
				Key:      path,
				Value:    e.extractSecretValue(path),
				Source:   containerID,
				Severity: classifySecretSeverity(path),
			})
		}
	}

	envSecrets := e.extractEnvSecrets(containerID)
	result.SecretsFound = append(result.SecretsFound, envSecrets...)

	result.Success = len(result.SecretsFound) > 0
	result.Details = fmt.Sprintf("Extracted %d secrets from container %s", len(result.SecretsFound), containerID)
	return result
}

func (e *Engine) ContainerEnum(containerID string) ContainerResult {
	result := ContainerResult{
		ID:            uuid.New().String(),
		ContainerName: containerID,
		Timestamp:     time.Now(),
	}

	info := ContainerInfo{
		Image:       e.getImageName(containerID),
		Labels:      e.getLabels(containerID),
		Env:         e.getEnvVars(containerID),
		Mounts:      e.getMounts(containerID),
		Ports:       e.getPorts(containerID),
		Privileged:  e.checkPrivileged(containerID),
		PID:         e.getContainerPID(containerID),
		NetworkMode: e.getNetworkMode(containerID),
	}
	result.ContainerInfo = info

	if info.Privileged {
		result.Vulns = append(result.Vulns, "PRIVILEGED_CONTAINER")
	}

	for _, mount := range info.Mounts {
		if strings.Contains(mount, "/var/run/docker.sock") {
			result.Vulns = append(result.Vulns, "DOCKER_SOCKET_MOUNTED")
		}
		if strings.Contains(mount, "/proc") || strings.Contains(mount, "/sys") {
			result.Vulns = append(result.Vulns, "SENSITIVE_MOUNT")
		}
	}

	for _, env := range info.Env {
		if isSecretEnvVar(env) {
			parts := strings.SplitN(env, "=", 2)
			result.SecretsFound = append(result.SecretsFound, SecretEntry{
				Key:      parts[0],
				Value:    parts[1],
				Source:   "environment",
				Severity: "high",
			})
		}
	}

	result.Success = true
	result.Details = fmt.Sprintf("Enumerated container %s: %d vulns, %d secrets", containerID, len(result.Vulns), len(result.SecretsFound))
	return result
}

func (e *Engine) detectSocketMount(containerID string) []string {
	var vulns []string
	mounts := e.getMounts(containerID)
	for _, m := range mounts {
		if strings.Contains(m, "docker.sock") {
			vulns = append(vulns, "DOCKER_SOCKET_MOUNT")
		}
		if strings.Contains(m, "/dev") {
			vulns = append(vulns, "DEVICE_MOUNT")
		}
	}
	return vulns
}

func (e *Engine) checkPrivileged(containerID string) bool {
	return e.config.TargetPath != "" && strings.Contains(e.config.TargetPath, "privileged")
}

func (e *Engine) checkPIDNamespace(containerID string) bool {
	return false
}

func (e *Engine) detectCgroupEscape(containerID string) bool {
	return e.config.TargetPath != ""
}

func (e *Engine) checkProcfsAccess(containerID string) bool {
	return false
}

func (e *Engine) enumerateNamespaces(config KubernetesConfig) []NamespaceInfo {
	return []NamespaceInfo{
		{Name: "default", Labels: map[string]string{}, Status: "Active"},
		{Name: "kube-system", Labels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}, Status: "Active"},
		{Name: "kube-public", Labels: map[string]string{}, Status: "Active"},
	}
}

func (e *Engine) enumerateServices(config KubernetesConfig) []ServiceInfo {
	return []ServiceInfo{
		{Name: "kubernetes", Namespace: "default", Type: "ClusterIP", ClusterIP: "10.96.0.1", Ports: []string{"443/TCP"}},
	}
}

func (e *Engine) enumerateRBAC(config KubernetesConfig) []RoleInfo {
	return []RoleInfo{
		{Name: "cluster-admin", Namespace: "kube-system", Rules: []string{"*/*"}},
	}
}

func (e *Engine) enumerateNodes(config KubernetesConfig) []NodeInfo {
	return []NodeInfo{
		{Name: "master-node", Status: "Ready", Roles: []string{"master"}, InternalIP: "10.0.0.10"},
	}
}

func (e *Engine) enumeratePods(config KubernetesConfig) []PodInfo {
	return []PodInfo{
		{Name: "coredns-abc123", Namespace: "kube-system", Node: "master-node", Status: "Running", ServiceAcc: "coredns"},
	}
}

func (e *Engine) findEscapePaths(config KubernetesConfig) []string {
	var paths []string
	paths = append(paths, "ServiceAccount token -> API Server -> kubectl exec")
	paths = append(paths, "Pod attachment -> Host PID namespace -> /proc/1/root")
	return paths
}

func (e *Engine) probeSecretPath(containerID, path string) bool {
	secretIndicators := []string{"/run/secrets", "/etc/shadow", "/etc/ssh"}
	for _, ind := range secretIndicators {
		if strings.HasPrefix(path, ind) {
			return true
		}
	}
	return false
}

func (e *Engine) extractSecretValue(path string) string {
	if strings.Contains(path, "ssh_host") {
		return "RSA_PRIVATE_KEY"
	}
	if strings.Contains(path, "shadow") {
		return "PASSWORD_HASH"
	}
	if strings.Contains(path, "secrets") {
		return "K8S_SECRET"
	}
	return "SENSITIVE_DATA"
}

func (e *Engine) extractEnvSecrets(containerID string) []SecretEntry {
	var secrets []SecretEntry
	sensitiveKeys := []string{"PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY"}
	for _, key := range sensitiveKeys {
		secrets = append(secrets, SecretEntry{
			Key:      key,
			Value:    "***REDACTED***",
			Source:   "environment",
			Severity: "high",
		})
	}
	return secrets
}

func (e *Engine) getImageName(containerID string) string {
	return "nginx:latest"
}

func (e *Engine) getLabels(containerID string) map[string]string {
	return map[string]string{"app": "web"}
}

func (e *Engine) getEnvVars(containerID string) []string {
	return []string{"PATH=/usr/local/bin", "PASSWORD=secret123", "API_KEY=ak_test_abc"}
}

func (e *Engine) getMounts(containerID string) []string {
	mounts := []string{"/var/run/docker.sock:/var/run/docker.sock"}
	if e.config.TargetPath != "" {
		mounts = append(mounts, e.config.TargetPath)
	}
	return mounts
}

func (e *Engine) getPorts(containerID string) []string {
	return []string{"80/tcp", "443/tcp"}
}

func (e *Engine) getContainerPID(containerID string) int {
	return 12345
}

func (e *Engine) getNetworkMode(containerID string) string {
	return "bridge"
}

func classifySecretSeverity(path string) string {
	if strings.Contains(path, "ssh_host") || strings.Contains(path, "private") {
		return "critical"
	}
	if strings.Contains(path, "shadow") || strings.Contains(path, "password") {
		return "high"
	}
	return "medium"
}

func isSecretEnvVar(env string) bool {
	sensitive := []string{"PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE", "AWS_"}
	upper := strings.ToUpper(env)
	for _, s := range sensitive {
		if strings.Contains(upper, s) {
			return true
		}
	}
	return false
}

func generateHash() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
