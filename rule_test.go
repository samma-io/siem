package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestEqualsMatch(t *testing.T) {
	rf := RuleFile{
		Name:        "test-equals",
		NATSSubject: "test.subject",
		Match: Condition{
			Field:  "type",
			Equals: "nmap",
		},
	}
	compiled, err := CompileRule(rf)
	if err != nil {
		t.Fatal(err)
	}

	event := map[string]interface{}{"type": "nmap", "target": "example.com"}
	if !compiled.Matcher(event) {
		t.Error("expected match")
	}

	event2 := map[string]interface{}{"type": "nikto"}
	if compiled.Matcher(event2) {
		t.Error("expected no match")
	}
}

func TestNestedFieldMatch(t *testing.T) {
	rf := RuleFile{
		Name:        "test-nested",
		NATSSubject: "test.subject",
		Match: Condition{
			Field:  "samma-io.scanner",
			Equals: "domain",
		},
	}
	compiled, err := CompileRule(rf)
	if err != nil {
		t.Fatal(err)
	}

	event := map[string]interface{}{
		"type": "nmap",
		"samma-io": map[string]interface{}{
			"scanner": "domain",
			"id":      "g23dE222",
		},
	}
	if !compiled.Matcher(event) {
		t.Error("expected match on nested field")
	}
}

func TestAndCondition(t *testing.T) {
	rf := RuleFile{
		Name:        "test-and",
		NATSSubject: "test.subject",
		Match: Condition{
			And: []Condition{
				{Field: "type", Equals: "nmap"},
				{Field: "protocol", Equals: "tcp"},
			},
		},
	}
	compiled, err := CompileRule(rf)
	if err != nil {
		t.Fatal(err)
	}

	hit := map[string]interface{}{"type": "nmap", "protocol": "tcp"}
	if !compiled.Matcher(hit) {
		t.Error("expected match")
	}

	miss := map[string]interface{}{"type": "nmap", "protocol": "udp"}
	if compiled.Matcher(miss) {
		t.Error("expected no match")
	}
}

func TestOrCondition(t *testing.T) {
	rf := RuleFile{
		Name:        "test-or",
		NATSSubject: "test.subject",
		Match: Condition{
			Or: []Condition{
				{Field: "type", Equals: "nmap"},
				{Field: "type", Equals: "Nikto"},
			},
		},
	}
	compiled, err := CompileRule(rf)
	if err != nil {
		t.Fatal(err)
	}

	nmap := map[string]interface{}{"type": "nmap"}
	if !compiled.Matcher(nmap) {
		t.Error("expected match for nmap")
	}

	nikto := map[string]interface{}{"type": "Nikto"}
	if !compiled.Matcher(nikto) {
		t.Error("expected match for Nikto")
	}

	other := map[string]interface{}{"type": "tsunami"}
	if compiled.Matcher(other) {
		t.Error("expected no match for tsunami")
	}
}

func TestRegexMatch(t *testing.T) {
	rf := RuleFile{
		Name:        "test-regex",
		NATSSubject: "test.subject",
		Match: Condition{
			Field: "finding",
			Regex: "(?i)directory traversal",
		},
	}
	compiled, err := CompileRule(rf)
	if err != nil {
		t.Fatal(err)
	}

	event := map[string]interface{}{
		"finding": "Possible Directory Traversal (CVE-2011-0966)",
	}
	if !compiled.Matcher(event) {
		t.Error("expected regex match")
	}

	noMatch := map[string]interface{}{
		"finding": "X-Frame-Options header not present",
	}
	if compiled.Matcher(noMatch) {
		t.Error("expected no regex match")
	}
}

func TestMissingFieldNoMatch(t *testing.T) {
	rf := RuleFile{
		Name:        "test-missing",
		NATSSubject: "test.subject",
		Match: Condition{
			Field:  "nonexistent.deep.field",
			Equals: "anything",
		},
	}
	compiled, err := CompileRule(rf)
	if err != nil {
		t.Fatal(err)
	}

	event := map[string]interface{}{"type": "nmap"}
	if compiled.Matcher(event) {
		t.Error("expected no match for missing field")
	}
}

func TestNestedAndOr(t *testing.T) {
	rf := RuleFile{
		Name:        "test-nested-logic",
		NATSSubject: "test.subject",
		Match: Condition{
			And: []Condition{
				{Field: "type", Equals: "Nikto"},
				{
					Or: []Condition{
						{Field: "finding", Regex: "(?i)sql injection"},
						{Field: "finding", Regex: "(?i)directory traversal"},
					},
				},
			},
		},
	}
	compiled, err := CompileRule(rf)
	if err != nil {
		t.Fatal(err)
	}

	hit := map[string]interface{}{
		"type":    "Nikto",
		"finding": "Possible SQL Injection",
	}
	if !compiled.Matcher(hit) {
		t.Error("expected match")
	}

	wrongType := map[string]interface{}{
		"type":    "nmap",
		"finding": "Possible SQL Injection",
	}
	if compiled.Matcher(wrongType) {
		t.Error("expected no match for wrong type")
	}

	wrongFinding := map[string]interface{}{
		"type":    "Nikto",
		"finding": "Missing header",
	}
	if compiled.Matcher(wrongFinding) {
		t.Error("expected no match for wrong finding")
	}
}

func TestInvalidRegexError(t *testing.T) {
	rf := RuleFile{
		Name:        "test-bad-regex",
		NATSSubject: "test.subject",
		Match: Condition{
			Field: "type",
			Regex: "[invalid",
		},
	}
	_, err := CompileRule(rf)
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestNoFieldOrLogicError(t *testing.T) {
	rf := RuleFile{
		Name:        "test-empty",
		NATSSubject: "test.subject",
		Match:       Condition{},
	}
	_, err := CompileRule(rf)
	if err == nil {
		t.Error("expected error for empty condition")
	}
}

func TestComplianceFieldsParsed(t *testing.T) {
	yamlData := `
name: test-compliance
description: Test compliance parsing
severity: high
nats_subject: test.subject
compliance:
  pci_dss:
    - "10.2.5"
  gdpr:
    - "IV_35.7.d"
    - "IV_32.2"
  hipaa:
    - "164.312.b"
  nist_800_53:
    - "AU.14"
    - "AC.7"
  mitre:
    - "T1078"
  tsc:
    - "CC6.1"
  gpg13:
    - "7.1"
match:
  field: type
  equals: test
`
	var rf RuleFile
	if err := yaml.Unmarshal([]byte(yamlData), &rf); err != nil {
		t.Fatal(err)
	}

	compiled, err := CompileRule(rf)
	if err != nil {
		t.Fatal(err)
	}

	if len(compiled.Compliance.PCIDSS) != 1 || compiled.Compliance.PCIDSS[0] != "10.2.5" {
		t.Errorf("expected PCI DSS [10.2.5], got %v", compiled.Compliance.PCIDSS)
	}
	if len(compiled.Compliance.GDPR) != 2 {
		t.Errorf("expected 2 GDPR entries, got %d", len(compiled.Compliance.GDPR))
	}
	if len(compiled.Compliance.HIPAA) != 1 || compiled.Compliance.HIPAA[0] != "164.312.b" {
		t.Errorf("expected HIPAA [164.312.b], got %v", compiled.Compliance.HIPAA)
	}
	if len(compiled.Compliance.NIST) != 2 {
		t.Errorf("expected 2 NIST entries, got %d", len(compiled.Compliance.NIST))
	}
	if len(compiled.Compliance.MITRE) != 1 || compiled.Compliance.MITRE[0] != "T1078" {
		t.Errorf("expected MITRE [T1078], got %v", compiled.Compliance.MITRE)
	}
	if len(compiled.Compliance.TSC) != 1 || compiled.Compliance.TSC[0] != "CC6.1" {
		t.Errorf("expected TSC [CC6.1], got %v", compiled.Compliance.TSC)
	}
	if len(compiled.Compliance.GPG13) != 1 || compiled.Compliance.GPG13[0] != "7.1" {
		t.Errorf("expected GPG13 [7.1], got %v", compiled.Compliance.GPG13)
	}
}

func TestComplianceOptional(t *testing.T) {
	rf := RuleFile{
		Name:        "test-no-compliance",
		NATSSubject: "test.subject",
		Match: Condition{
			Field:  "type",
			Equals: "nmap",
		},
	}
	compiled, err := CompileRule(rf)
	if err != nil {
		t.Fatal(err)
	}

	if compiled.Compliance.PCIDSS != nil {
		t.Error("expected nil PCI DSS for rule without compliance")
	}
	if compiled.Compliance.MITRE != nil {
		t.Error("expected nil MITRE for rule without compliance")
	}
}

func TestRulesAgainstTestData(t *testing.T) {
	rulesDir := os.Getenv("SIEM_RULES_DIR")
	testDir := os.Getenv("SIEM_TEST_DIR")
	if rulesDir == "" || testDir == "" {
		t.Skip("SIEM_RULES_DIR and SIEM_TEST_DIR not set, skipping integration test")
	}

	ruleCount := 0
	err := filepath.WalkDir(rulesDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".yaml") && !strings.HasSuffix(d.Name(), ".yml") {
			return nil
		}

		// Load and compile the rule
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("reading rule %s: %v", path, err)
			return nil
		}

		var rf RuleFile
		if err := yaml.Unmarshal(data, &rf); err != nil {
			t.Errorf("parsing rule %s: %v", path, err)
			return nil
		}

		compiled, err := CompileRule(rf)
		if err != nil {
			t.Errorf("compiling rule %s: %v", path, err)
			return nil
		}

		// Determine matching test JSON path
		// rules/k8s/k8s_user_login.yaml -> test/k8s/k8s_user_login.json
		relPath, _ := filepath.Rel(rulesDir, path)
		ext := filepath.Ext(relPath)
		testPath := filepath.Join(testDir, strings.TrimSuffix(relPath, ext)+".json")

		testData, err := os.ReadFile(testPath)
		if err != nil {
			t.Errorf("rule %q: missing test file %s: %v", rf.Name, testPath, err)
			return nil
		}

		var event map[string]interface{}
		if err := json.Unmarshal(testData, &event); err != nil {
			t.Errorf("rule %q: invalid test JSON %s: %v", rf.Name, testPath, err)
			return nil
		}

		if !compiled.Matcher(event) {
			t.Errorf("rule %q: did NOT match test event from %s", rf.Name, testPath)
		} else {
			t.Logf("rule %q: matched test event from %s", rf.Name, testPath)
		}

		ruleCount++
		return nil
	})
	if err != nil {
		t.Fatalf("walking rules dir: %v", err)
	}

	if ruleCount == 0 {
		t.Error("no rules found in SIEM_RULES_DIR")
	}
	t.Logf("tested %d rules against their test data", ruleCount)
}
