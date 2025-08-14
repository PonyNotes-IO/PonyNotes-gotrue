package sms_provider

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/utilities"
)

const (
	aliyunSMSEndpoint = "https://dysmsapi.aliyuncs.com"
	aliyunAPIVersion  = "2017-05-25"
)

type AliyunProvider struct {
	Config *conf.AliyunProviderConfiguration
}

type AliyunSMSResponse struct {
	Message   string `json:"Message"`
	RequestId string `json:"RequestId"`
	BizId     string `json:"BizId"`
	Code      string `json:"Code"`
}

// Creates a SmsProvider with the Aliyun Config
func NewAliyunProvider(config conf.AliyunProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &AliyunProvider{
		Config: &config,
	}, nil
}

func (a *AliyunProvider) SendMessage(phone, message, channel, otp string) (string, error) {
	if channel != SMSProvider {
		return "", fmt.Errorf("channel type %q is not supported for Aliyun SMS", channel)
	}
	return a.SendSMS(phone, message, otp)
}

func (a *AliyunProvider) SendSMS(phone, message, otp string) (string, error) {
	// 构建请求参数
	params := map[string]string{
		"AccessKeyId":      a.Config.AccessKeyId,
		"Action":           "SendSms",
		"Format":           "JSON",
		"PhoneNumbers":     phone,
		"RegionId":         "cn-hangzhou",
		"SignName":         a.Config.SignName,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   uuid.New().String(),
		"SignatureVersion": "1.0",
		"TemplateCode":     a.Config.TemplateCode,
		"TemplateParam":    fmt.Sprintf(`{"code":"%s"}`, otp),
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"Version":          aliyunAPIVersion,
	}

	// 生成签名
	signature := a.generateSignature(params)
	params["Signature"] = signature

	// 构建请求URL
	reqURL := aliyunSMSEndpoint + "/?" + a.buildQueryString(params)

	// 发送HTTP请求
	client := &http.Client{Timeout: defaultTimeout}
	resp, err := client.Get(reqURL)
	if err != nil {
		return "", fmt.Errorf("failed to send SMS request: %v", err)
	}
	defer utilities.SafeClose(resp.Body)

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	var smsResp AliyunSMSResponse
	if err := json.Unmarshal(body, &smsResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	// 检查响应状态
	if smsResp.Code != "OK" {
		return "", fmt.Errorf("aliyun SMS error: %s - %s", smsResp.Code, smsResp.Message)
	}

	return smsResp.BizId, nil
}

func (a *AliyunProvider) VerifyOTP(phone, token string) error {
	return fmt.Errorf("VerifyOTP is not supported for Aliyun SMS")
}

// generateSignature 生成阿里云API签名
func (a *AliyunProvider) generateSignature(params map[string]string) string {
	// 1. 排序参数
	var keys []string
	for k := range params {
		if k != "Signature" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	// 2. 构建规范化查询字符串
	var query []string
	for _, k := range keys {
		query = append(query, a.percentEncode(k)+"="+a.percentEncode(params[k]))
	}
	canonicalizedQueryString := strings.Join(query, "&")

	// 3. 构建待签名字符串
	stringToSign := "GET&" + a.percentEncode("/") + "&" + a.percentEncode(canonicalizedQueryString)

	// 4. 计算签名
	key := a.Config.AccessKeySecret + "&"
	h := hmac.New(sha1.New, []byte(key))
	h.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return signature
}

// percentEncode 进行百分号编码
func (a *AliyunProvider) percentEncode(str string) string {
	str = url.QueryEscape(str)
	str = strings.ReplaceAll(str, "+", "%20")
	str = strings.ReplaceAll(str, "*", "%2A")
	str = strings.ReplaceAll(str, "%7E", "~")
	return str
}

// buildQueryString 构建查询字符串
func (a *AliyunProvider) buildQueryString(params map[string]string) string {
	var query []string
	for k, v := range params {
		query = append(query, k+"="+url.QueryEscape(v))
	}
	return strings.Join(query, "&")
}
