package main

import (
	"database/sql"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCapabilityTokenIsOpaqueAndHashable(t *testing.T) {
	token, tokenHash, err := newCapabilityToken()
	if err != nil {
		t.Fatal(err)
	}
	if !validCapabilityToken(token) {
		t.Fatal("generated token should be valid")
	}
	if tokenHash != hashCapabilityToken(token) {
		t.Fatal("token hash mismatch")
	}
	if len(token) != 47 {
		t.Fatalf("unexpected token length: %d", len(token))
	}
	if validCapabilityToken("frm_example") {
		t.Fatal("short illustrative token must be rejected")
	}
}

func TestNormalizeFormTTL(t *testing.T) {
	ttl, err := normalizeFormTTL(0)
	if err != nil || ttl != defaultFormTTL {
		t.Fatalf("default ttl = %v, err = %v", ttl, err)
	}
	if _, err := normalizeFormTTL(60); err == nil {
		t.Fatal("ttl below minimum should fail")
	}
	if _, err := normalizeFormTTL(int(maxFormTTL.Seconds()) + 1); err == nil {
		t.Fatal("ttl above maximum should fail")
	}
}

func TestNormalizeFormFieldsRejectsUnsafeDefinition(t *testing.T) {
	_, err := normalizeFormFields([]formField{{Name: "email", Type: "email"}, {Name: "email", Type: "text"}})
	if err == nil {
		t.Fatal("duplicate fields should fail")
	}
	_, err = normalizeFormFields([]formField{{Name: "profile.role", Type: "text"}})
	if err == nil {
		t.Fatal("unsafe field name should fail")
	}
	_, err = normalizeFormFields([]formField{{Name: "course", Type: "select"}})
	if err == nil {
		t.Fatal("select without options should fail")
	}
}

func TestValidateFormAnswers(t *testing.T) {
	fields := []formField{
		{Name: "email", Label: "E-mail", Type: "email", Required: true},
		{Name: "phone", Label: "Telefone", Type: "tel", Required: true},
		{Name: "course", Label: "Curso", Type: "select", Options: []string{"IA", "Vendas"}, Required: true},
		{Name: "consent", Label: "Consentimento", Type: "checkbox", Required: true},
	}
	values := url.Values{
		"email":   {"aluna@example.com"},
		"phone":   {"+55 (21) 99999-9999"},
		"course":  {"IA"},
		"consent": {"true"},
	}
	answers, err := validateFormAnswers(fields, values)
	if err != nil {
		t.Fatal(err)
	}
	if answers["course"] != "IA" {
		t.Fatalf("unexpected answer: %q", answers["course"])
	}

	values.Set("course", "Outro")
	if _, err := validateFormAnswers(fields, values); err == nil {
		t.Fatal("unknown select option should fail")
	}
	values.Set("course", "IA")
	values.Set("consent", "false")
	if _, err := validateFormAnswers(fields, values); err == nil {
		t.Fatal("invalid checkbox value should fail")
	}
	values.Set("consent", "true")
	values.Del("email")
	if _, err := validateFormAnswers(fields, values); err == nil {
		t.Fatal("missing required field should fail")
	}
}

func TestFormAvailability(t *testing.T) {
	now := time.Now().UTC()
	if err := formAvailability(formInstance{ExpiresAt: now.Add(time.Minute)}, now); err != nil {
		t.Fatal(err)
	}
	if err := formAvailability(formInstance{ExpiresAt: now.Add(-time.Second)}, now); !errors.Is(err, errFormExpired) {
		t.Fatalf("expected expired, got %v", err)
	}
	if err := formAvailability(formInstance{ExpiresAt: now.Add(time.Minute), UsedAt: sqlNullTime(now)}, now); !errors.Is(err, errFormUsed) {
		t.Fatalf("expected used, got %v", err)
	}
}

func TestFormSecurityHeaders(t *testing.T) {
	recorder := httptest.NewRecorder()
	setFormSecurityHeaders(recorder)
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("form responses must not be cached")
	}
	if recorder.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("form token must not leak through referrer")
	}
	if !strings.Contains(recorder.Header().Get("Content-Security-Policy"), "form-action 'self'") {
		t.Fatal("form action must be restricted to same origin")
	}
}

func sqlNullTime(value time.Time) sql.NullTime {
	return sql.NullTime{Time: value, Valid: true}
}
