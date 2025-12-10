package third_party_provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/supabase/auth/internal/conf"
)

// WeiXinProvider 封装微信OAuth认证与用户信息获取的结构体
type WeiXinProvider struct {
	AccessToken string          // 调用凭证
	OpenId      string          // 微信openid
	UnionId     string          // 微信unionid（可选）
	UserInfo    *WeiXinUserInfo // 用户详细资料结构体
}

// NewWeiXinProvider 完成access_token获取与openid初始化
func NewWeiXinProvider(code string, config conf.WeiXinProviderConfiguration) (ThirdPartyProvider, error) {
	// 构造API请求URL
	params := url.Values{}
	params.Add("appid", config.ClientKey)
	params.Add("secret", config.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	tokenURL := "https://api.weixin.qq.com/sns/oauth2/access_token?" + params.Encode()

	resp, err := http.Get(tokenURL)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var tokenResp WeiXinAccessTokenResponse
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, errors.New("微信access_token响应解析失败")
	}
	// 检查微信错误码
	if tokenResp.ErrCode != 0 {
		return nil, fmt.Errorf("微信接口错误: %d %s", tokenResp.ErrCode, tokenResp.ErrMsg)
	}

	provider := &WeiXinProvider{
		AccessToken: tokenResp.AccessToken,
		OpenId:      tokenResp.OpenId,
		UnionId:     tokenResp.UnionId,
	}
	return provider, nil
}

// GetProviderId 返回微信unionid，作为唯一provider id
// 如果unionid为空，则使用openid作为fallback
func (w *WeiXinProvider) GetProviderId() *string {
	if strings.TrimSpace(w.UnionId) != "" {
		return &w.UnionId
	}
	// 如果unionid为空，使用openid作为provider id
	return &w.OpenId
}

// GetUserMeta 获取用户详细信息，并格式化为map供userMeta落库
func (w *WeiXinProvider) GetUserMeta() (map[string]any, error) {
	// 构造用户信息接口URL
	params := url.Values{}
	params.Add("access_token", w.AccessToken)
	params.Add("openid", w.OpenId)
	params.Add("lang", "zh_CN")
	userInfoURL := "https://api.weixin.qq.com/sns/userinfo?" + params.Encode()

	resp, err := http.Get(userInfoURL)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var userInfo WeiXinUserInfo
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, errors.New("微信用户信息响应解析失败")
	}
	// 检查微信返回的错误码
	if userInfo.ErrCode != 0 {
		return nil, fmt.Errorf("微信接口错误: %d %s", userInfo.ErrCode, userInfo.ErrMsg)
	}

	// 填充到结构体
	w.UserInfo = &userInfo
	// 更新UnionId（如果用户信息中有的话）
	if userInfo.UnionId != "" {
		w.UnionId = userInfo.UnionId
	}
	
	// 确定provider id（优先使用unionid，如果为空则使用openid）
	providerId := w.OpenId
	if strings.TrimSpace(w.UnionId) != "" {
		providerId = w.UnionId
	}
	
	// 构建userMeta，后续可根据业务拓展
	userMeta := map[string]any{
		"sub":       providerId, // 设置sub字段，用于NewIdentity
		"openid":    userInfo.OpenId,
		"nickname":  userInfo.Nickname,
		"avatar":    userInfo.HeadImgUrl,
		"province":  userInfo.Province,
		"city":      userInfo.City,
		"country":   userInfo.Country,
		"sex":       userInfo.Sex,       // 1为男，2为女
		"privilege": userInfo.Privilege, // 特权信息
	}
	if userInfo.UnionId != "" {
		userMeta["unionid"] = userInfo.UnionId
	}
	return userMeta, nil
}

// WeiXinAccessTokenResponse 微信 access_token 接口响应结构
type WeiXinAccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	OpenId       string `json:"openid"`
	Scope        string `json:"scope"`
	UnionId      string `json:"unionid,omitempty"`
	ErrCode      int    `json:"errcode,omitempty"`
	ErrMsg       string `json:"errmsg,omitempty"`
}

// 微信 用户信息接口响应结构
type WeiXinUserInfo struct {
	OpenId     string   `json:"openid"`
	Nickname   string   `json:"nickname"`
	Sex        int      `json:"sex"` // 1为男，2为女
	Province   string   `json:"province"`
	City       string   `json:"city"`
	Country    string   `json:"country"`
	HeadImgUrl string   `json:"headimgurl"`
	Privilege  []string `json:"privilege"`
	UnionId    string   `json:"unionid,omitempty"`
	ErrCode    int      `json:"errcode,omitempty"`
	ErrMsg     string   `json:"errmsg,omitempty"`
}
