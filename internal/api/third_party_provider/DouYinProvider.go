package third_party_provider

import (
	"encoding/json"
	"errors"

	credential "github.com/bytedance/douyin-openapi-credential-go/client"
	openApiSdkClient "github.com/bytedance/douyin-openapi-sdk-go/client"
	"github.com/supabase/auth/internal/conf"
)

type DouYinProvider struct {
	SdkClient          *openApiSdkClient.Client
	OAuthAccessToken   *openApiSdkClient.OauthAccessTokenResponseData
	V1AuthGetRelatedId *openApiSdkClient.V1AuthGetRelatedIdResponseData
}

const GrantType string = "authorization_code"

// NewDouYinProvider
func NewDouYinProvider(code string, config conf.DouYinProviderConfiguration) (ThirdPartyProvider, error) {
	// 初始化SDK client
	opt := new(credential.Config).
		SetClientKey(config.ClientKey).      // 改成自己的app_id
		SetClientSecret(config.ClientSecret) // 改成自己的secret
	sdkClient, err := openApiSdkClient.NewClient(opt)
	if err != nil {
		return nil, err
	}

	OAuthAccessTokenRequest := &openApiSdkClient.OauthAccessTokenRequest{}
	OAuthAccessTokenRequest.SetClientKey(config.ClientKey)
	OAuthAccessTokenRequest.SetClientSecret(config.ClientSecret)
	OAuthAccessTokenRequest.SetCode(code)
	OAuthAccessTokenRequest.SetGrantType(GrantType)
	// sdk调用
	OAuthAccessToken, err := sdkClient.OauthAccessToken(OAuthAccessTokenRequest)
	if err != nil {
		return nil, errors.New("抖音 OAuthAccessToken 调用失败: " + err.Error())
	}

	// 检查 OAuthAccessToken 响应
	if OAuthAccessToken == nil || OAuthAccessToken.Data == nil {
		return nil, errors.New("抖音 OAuthAccessToken 响应为空")
	}
	if OAuthAccessToken.Data.AccessToken == nil || *OAuthAccessToken.Data.AccessToken == "" {
		return nil, errors.New("抖音 OAuthAccessToken 返回的 access_token 为空")
	}
	if OAuthAccessToken.Data.OpenId == nil || *OAuthAccessToken.Data.OpenId == "" {
		return nil, errors.New("抖音 OAuthAccessToken 返回的 open_id 为空")
	}

	// 尝试调用 V1AuthGetRelatedId 获取 AlliedId
	// 如果失败，使用 OpenId 作为 fallback
	var v1AuthGetRelatedIdData *openApiSdkClient.V1AuthGetRelatedIdResponseData
	V1AuthGetRelatedIdRequest := &openApiSdkClient.V1AuthGetRelatedIdRequest{}
	V1AuthGetRelatedIdRequest.SetAccessToken(*OAuthAccessToken.Data.AccessToken)
	V1AuthGetRelatedIdRequest.SetOpenId(*OAuthAccessToken.Data.OpenId)
	// sdk调用
	V1AuthGetRelatedId, err := sdkClient.V1AuthGetRelatedId(V1AuthGetRelatedIdRequest)
	if err != nil {
		// V1AuthGetRelatedId 调用失败，使用 OpenId 作为 fallback
		// 这是可接受的，因为 OpenId 也可以作为唯一标识
		v1AuthGetRelatedIdData = nil
	} else {
		// 检查 V1AuthGetRelatedId 响应
		if V1AuthGetRelatedId != nil {
			// 检查sdk响应错误代码（如果响应结构有 ErrNo 字段）
			if V1AuthGetRelatedId.ErrNo != nil && *V1AuthGetRelatedId.ErrNo != 0 {
				// 有错误码，但不影响，使用 OpenId 作为 fallback
				v1AuthGetRelatedIdData = nil
			} else if V1AuthGetRelatedId.Data != nil {
				// 成功获取 AlliedId
				v1AuthGetRelatedIdData = V1AuthGetRelatedId.Data
			} else {
				// Data 为空，使用 OpenId 作为 fallback
				v1AuthGetRelatedIdData = nil
			}
		} else {
			// 响应为空，使用 OpenId 作为 fallback
			v1AuthGetRelatedIdData = nil
		}
	}

	return &DouYinProvider{SdkClient: sdkClient, OAuthAccessToken: OAuthAccessToken.Data, V1AuthGetRelatedId: v1AuthGetRelatedIdData}, nil
}

func (p *DouYinProvider) GetProviderId() *string {
	// 优先使用 AlliedId（如果 V1AuthGetRelatedId 调用成功）
	if p.V1AuthGetRelatedId != nil && p.V1AuthGetRelatedId.AlliedId != nil && *p.V1AuthGetRelatedId.AlliedId != "" {
	return p.V1AuthGetRelatedId.AlliedId
	}
	// Fallback: 使用 OpenId 作为 provider id
	if p.OAuthAccessToken != nil && p.OAuthAccessToken.OpenId != nil {
		return p.OAuthAccessToken.OpenId
	}
	return nil
}

func (p *DouYinProvider) GetUserMeta() (map[string]any, error) {
	// 确保 userMeta 包含 "sub" 字段（用于 NewIdentity）
	providerId := p.GetProviderId()
	if providerId == nil || *providerId == "" {
		if p.OAuthAccessToken != nil && p.OAuthAccessToken.OpenId != nil {
			providerId = p.OAuthAccessToken.OpenId
		} else {
			return nil, errors.New("无法获取抖音用户标识")
		}
	}

	// 尝试获取用户详细信息
	sdkRequest := &openApiSdkClient.OauthUserinfoRequest{}
	sdkRequest.SetAccessToken(*p.OAuthAccessToken.AccessToken)
	sdkRequest.SetOpenId(*p.OAuthAccessToken.OpenId)
	// sdk调用
	OauthUserinfo, err := p.SdkClient.OauthUserinfo(sdkRequest)
	if err != nil {
		// OauthUserinfo 调用失败，返回基本的用户信息
		return map[string]any{
			"sub": *providerId,
		}, nil
	}
	
	// 检查sdk响应错误代码
	if OauthUserinfo.ErrNo != nil && *OauthUserinfo.ErrNo != 0 {
		// 有错误码，返回基本的用户信息
		return map[string]any{
			"sub": *providerId,
		}, nil
	}

	// 成功获取用户信息
	data, err := json.Marshal(DouYinUserInfo{OAuthAccessToken: p.OAuthAccessToken, OauthUserinfo: OauthUserinfo.Data})
	if err != nil {
		// JSON 序列化失败，返回基本的用户信息
		return map[string]any{
			"sub": *providerId,
		}, nil
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		// JSON 反序列化失败，返回基本的用户信息
		return map[string]any{
			"sub": *providerId,
		}, nil
	}

	// 确保 result 包含 "sub" 字段
		result["sub"] = *providerId

	return result, nil
}

type DouYinUserInfo struct {
	OAuthAccessToken *openApiSdkClient.OauthAccessTokenResponseData
	OauthUserinfo    *openApiSdkClient.OauthUserinfoResponseData
}
