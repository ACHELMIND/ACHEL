package implantgen

import (
	"fmt"
)

func NewPayloadEncryptor(key []byte) *PayloadEncryptor {
	return &PayloadEncryptor{key: key}
}

func (pe *PayloadEncryptor) Encrypt(data []byte) ([]byte, error) {
	return encryptPayload(data, pe.key)
}

func (pe *PayloadEncryptor) Decrypt(data []byte) ([]byte, error) {
	return decryptPayload(data, pe.key)
}

func NewTemplateManager() *TemplateManager {
	return &TemplateManager{
		templates: make(map[string]*templateEntry),
	}
}

func (tm *TemplateManager) Add(name string, info TemplateInfo, data []byte) {
	tm.templates[name] = &templateEntry{
		data: data,
		info: info,
	}
}

func (tm *TemplateManager) Get(name string) (*TemplateInfo, []byte, bool) {
	entry, ok := tm.templates[name]
	if !ok {
		return nil, nil, false
	}
	info := entry.info
	return &info, entry.data, true
}

func (tm *TemplateManager) Remove(name string) error {
	if _, ok := tm.templates[name]; !ok {
		return fmt.Errorf("template %s not found", name)
	}
	delete(tm.templates, name)
	return nil
}

func (tm *TemplateManager) List() []TemplateInfo {
	result := make([]TemplateInfo, 0, len(tm.templates))
	for _, entry := range tm.templates {
		result = append(result, entry.info)
	}
	return result
}

func (tm *TemplateManager) Count() int {
	return len(tm.templates)
}
