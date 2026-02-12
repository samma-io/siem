package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Compliance struct {
	PCIDSS []string `yaml:"pci_dss,omitempty" json:"pci_dss,omitempty"`
	GDPR   []string `yaml:"gdpr,omitempty" json:"gdpr,omitempty"`
	HIPAA  []string `yaml:"hipaa,omitempty" json:"hipaa,omitempty"`
	NIST   []string `yaml:"nist_800_53,omitempty" json:"nist_800_53,omitempty"`
	MITRE  []string `yaml:"mitre,omitempty" json:"mitre,omitempty"`
	TSC    []string `yaml:"tsc,omitempty" json:"tsc,omitempty"`
	GPG13  []string `yaml:"gpg13,omitempty" json:"gpg13,omitempty"`
}

type RuleFile struct {
	Name        string     `yaml:"name"`
	Description string     `yaml:"description"`
	Severity    string     `yaml:"severity"`
	NATSSubject string     `yaml:"nats_subject"`
	Compliance  Compliance `yaml:"compliance"`
	Match       Condition  `yaml:"match"`
}

type Condition struct {
	Field  string `yaml:"field,omitempty"`
	Equals string `yaml:"equals,omitempty"`
	Regex  string `yaml:"regex,omitempty"`

	And []Condition `yaml:"and,omitempty"`
	Or  []Condition `yaml:"or,omitempty"`
}

type CompiledRule struct {
	Name        string
	Description string
	Severity    string
	NATSSubject string
	Compliance  Compliance
	Matcher     func(event map[string]interface{}) bool
}

func CompileRule(rf RuleFile) (CompiledRule, error) {
	matcher, err := compileCondition(rf.Match)
	if err != nil {
		return CompiledRule{}, fmt.Errorf("rule %q: %w", rf.Name, err)
	}
	return CompiledRule{
		Name:        rf.Name,
		Description: rf.Description,
		Severity:    rf.Severity,
		NATSSubject: rf.NATSSubject,
		Compliance:  rf.Compliance,
		Matcher:     matcher,
	}, nil
}

func compileCondition(c Condition) (func(map[string]interface{}) bool, error) {
	if len(c.And) > 0 {
		var matchers []func(map[string]interface{}) bool
		for _, sub := range c.And {
			m, err := compileCondition(sub)
			if err != nil {
				return nil, err
			}
			matchers = append(matchers, m)
		}
		return func(event map[string]interface{}) bool {
			for _, m := range matchers {
				if !m(event) {
					return false
				}
			}
			return true
		}, nil
	}

	if len(c.Or) > 0 {
		var matchers []func(map[string]interface{}) bool
		for _, sub := range c.Or {
			m, err := compileCondition(sub)
			if err != nil {
				return nil, err
			}
			matchers = append(matchers, m)
		}
		return func(event map[string]interface{}) bool {
			for _, m := range matchers {
				if m(event) {
					return true
				}
			}
			return false
		}, nil
	}

	if c.Field == "" {
		return nil, fmt.Errorf("condition has no field, and, or or")
	}

	fieldPath := strings.Split(c.Field, ".")

	if c.Equals != "" {
		target := c.Equals
		return func(event map[string]interface{}) bool {
			val := getNestedField(event, fieldPath)
			if val == nil {
				return false
			}
			return fmt.Sprintf("%v", val) == target
		}, nil
	}

	if c.Regex != "" {
		re, err := regexp.Compile(c.Regex)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q for field %q: %w", c.Regex, c.Field, err)
		}
		return func(event map[string]interface{}) bool {
			val := getNestedField(event, fieldPath)
			if val == nil {
				return false
			}
			return re.MatchString(fmt.Sprintf("%v", val))
		}, nil
	}

	return nil, fmt.Errorf("field %q has neither equals nor regex", c.Field)
}

func getNestedField(data map[string]interface{}, path []string) interface{} {
	var current interface{} = data
	for _, key := range path {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current, ok = m[key]
		if !ok {
			return nil
		}
	}
	return current
}

func LoadRules(dir string) ([]CompiledRule, error) {
	var rules []CompiledRule

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}

		var rf RuleFile
		if err := yaml.Unmarshal(data, &rf); err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}

		compiled, err := CompileRule(rf)
		if err != nil {
			return fmt.Errorf("compiling %s: %w", path, err)
		}

		rules = append(rules, compiled)
		log.Printf("loaded rule: %s (severity=%s, subject=%s)", compiled.Name, compiled.Severity, compiled.NATSSubject)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking rules dir %q: %w", dir, err)
	}

	return rules, nil
}
