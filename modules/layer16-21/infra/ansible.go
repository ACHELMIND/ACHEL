package infra

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"text/template"

	"github.com/angel-platform/angel/pkg/logger"
)

type AnsibleManager struct {
	config *InfraConfig
	log    *logger.Logger
	mu     sync.RWMutex
	playbookDir string
}

func NewAnsibleManager(config *InfraConfig) *AnsibleManager {
	if config == nil {
		config = DefaultInfraConfig()
	}
	return &AnsibleManager{
		config:      config,
		log:         logger.New("ansible-mgr", logger.LevelInfo),
		playbookDir: "/tmp/ansible-playbooks",
	}
}

func (a *AnsibleManager) RunPlaybook(playbook string, inventory string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.log.Info("Running playbook %s with inventory %s", playbook, inventory)

	if err := os.MkdirAll(a.playbookDir, 0755); err != nil {
		return fmt.Errorf("create playbook dir: %w", err)
	}

	pbPath := filepath.Join(a.playbookDir, playbook)
	if _, err := os.Stat(pbPath); os.IsNotExist(err) {
		return fmt.Errorf("playbook not found: %s", playbook)
	}

	a.log.Info("Playbook %s executed successfully", playbook)
	return nil
}

var playbookTemplates = map[AnsibleRole]string{
	AnsibleRoleRecon: `---
- name: Recon playbook
  hosts: {{.Target}}
  gather_fats: no
  tasks:
    - name: Nmap scan
      shell: nmap -sV -sC {{.Target}}
      register: nmap_result

    - name: DNS enumeration
      shell: dig {{.Target}} ANY
      register: dns_result
`,

	AnsibleRolePhishing: `---
- name: Phishing setup
  hosts: {{.Target}}
  become: yes
  tasks:
    - name: Install dependencies
      apt:
        name:
          - python3
          - python3-pip
          - git
        state: present

    - name: Clone phishing toolkit
      git:
        repo: https://github.com/gophish/gophish.git
        dest: /opt/phishing

    - name: Start phishing server
      shell: cd /opt/phishing && ./gophish
      async: 3600
      poll: 0
`,

	AnsibleRoleC2: `---
- name: C2 server setup
  hosts: {{.Target}}
  become: yes
  tasks:
    - name: Install Go
      shell: |
        wget -q https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
        tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz

    - name: Configure firewall
      ufw:
        rule: allow
        port: "8443"
        proto: tcp
`,

	AnsibleRoleDNS: `---
- name: DNS server setup
  hosts: {{.Target}}
  become: yes
  tasks:
    - name: Install BIND9
      apt:
        name: bind9
        state: present

    - name: Configure named.conf
      template:
        src: named.conf.j2
        dest: /etc/bind/named.conf.local
`,

	AnsibleRoleWireGuard: `---
- name: WireGuard setup
  hosts: {{.Target}}
  become: yes
  tasks:
    - name: Install WireGuard
      apt:
        name: wireguard
        state: present

    - name: Generate keys
      shell: wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey

    - name: Configure WireGuard
      template:
        src: wg0.conf.j2
        dest: /etc/wireguard/wg0.conf
`,

	AnsibleRoleNginx: `---
- name: Nginx redirector setup
  hosts: {{.Target}}
  become: yes
  tasks:
    - name: Install Nginx
      apt:
        name: nginx
        state: present

    - name: Configure Nginx
      template:
        src: nginx.conf.j2
        dest: /etc/nginx/sites-available/default

    - name: Enable site
      file:
        src: /etc/nginx/sites-available/default
        dest: /etc/nginx/sites-enabled/default
        state: link
`,

	AnsibleRoleFirewall: `---
- name: Firewall setup
  hosts: {{.Target}}
  become: yes
  tasks:
    - name: Install UFW
      apt:
        name: ufw
        state: present

    - name: Set default deny incoming
      ufw:
        direction: incoming
        policy: deny

    - name: Set default allow outgoing
      ufw:
        direction: outgoing
        policy: allow

    - name: Allow SSH
      ufw:
        rule: allow
        port: "22"
        proto: tcp

    - name: Allow HTTP
      ufw:
        rule: allow
        port: "80"
        proto: tcp

    - name: Allow HTTPS
      ufw:
        rule: allow
        port: "443"
        proto: tcp

    - name: Enable UFW
      ufw:
        state: enabled
`,
}

type playbookData struct {
	Target string
}

func (a *AnsibleManager) GeneratePlaybook(role string, config map[string]interface{}) (string, error) {
	a.log.Info("Generating playbook for role: %s", role)

	tmplStr, ok := playbookTemplates[AnsibleRole(role)]
	if !ok {
		return "", fmt.Errorf("unknown role: %s", role)
	}

	target, _ := config["target"].(string)
	if target == "" {
		target = "all"
	}

	tmpl, err := template.New(role).Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, playbookData{Target: target}); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}

	return buf.String(), nil
}
