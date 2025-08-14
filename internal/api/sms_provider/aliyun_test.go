package sms_provider

import (
	"testing"

	"github.com/supabase/auth/internal/conf"
)

func TestNewAliyunProvider(t *testing.T) {
	// Test with valid configuration
	config := conf.AliyunProviderConfiguration{
		AccessKeyId:     "test_access_key_id",
		AccessKeySecret: "test_access_key_secret",
		SignName:        "test_sign_name",
		TemplateCode:    "test_template_code",
	}

	provider, err := NewAliyunProvider(config)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if provider == nil {
		t.Fatal("Expected provider to be non-nil")
	}

	aliyunProvider, ok := provider.(*AliyunProvider)
	if !ok {
		t.Fatal("Expected provider to be of type *AliyunProvider")
	}

	if aliyunProvider.Config.AccessKeyId != config.AccessKeyId {
		t.Errorf("Expected AccessKeyId %s, got %s", config.AccessKeyId, aliyunProvider.Config.AccessKeyId)
	}
}

func TestNewAliyunProvider_InvalidConfig(t *testing.T) {
	// Test with invalid configuration (empty AccessKeyId)
	config := conf.AliyunProviderConfiguration{
		AccessKeyId:     "",
		AccessKeySecret: "test_access_key_secret",
		SignName:        "test_sign_name",
		TemplateCode:    "test_template_code",
	}

	_, err := NewAliyunProvider(config)
	if err == nil {
		t.Fatal("Expected error for invalid configuration, got nil")
	}
}

func TestAliyunProvider_PercentEncode(t *testing.T) {
	config := conf.AliyunProviderConfiguration{
		AccessKeyId:     "test_access_key_id",
		AccessKeySecret: "test_access_key_secret",
		SignName:        "test_sign_name",
		TemplateCode:    "test_template_code",
	}

	provider, _ := NewAliyunProvider(config)
	aliyunProvider := provider.(*AliyunProvider)

	testCases := []struct {
		input    string
		expected string
	}{
		{"test", "test"},
		{"test space", "test%20space"},
		{"test*", "test%2A"},
		{"test~", "test~"},
		{"test+", "test%2B"},
	}

	for _, tc := range testCases {
		result := aliyunProvider.percentEncode(tc.input)
		if result != tc.expected {
			t.Errorf("percentEncode(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
}

func TestAliyunProvider_GenerateSignature(t *testing.T) {
	config := conf.AliyunProviderConfiguration{
		AccessKeyId:     "test_access_key_id",
		AccessKeySecret: "test_access_key_secret",
		SignName:        "test_sign_name",
		TemplateCode:    "test_template_code",
	}

	provider, _ := NewAliyunProvider(config)
	aliyunProvider := provider.(*AliyunProvider)

	params := map[string]string{
		"Action":     "SendSms",
		"AccessKeyId": "test_access_key_id",
		"Version":    "2017-05-25",
	}

	signature := aliyunProvider.generateSignature(params)
	if signature == "" {
		t.Error("Expected non-empty signature")
	}

	// Test that signature is consistent
	signature2 := aliyunProvider.generateSignature(params)
	if signature != signature2 {
		t.Error("Expected signature to be consistent")
	}
}
