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

// NewDouYinProvider todo 是否需要，多个app使用同一标识
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
		return nil, err
	}

	V1AuthGetRelatedIdRequest := &openApiSdkClient.V1AuthGetRelatedIdRequest{}
	V1AuthGetRelatedIdRequest.SetAccessToken(*OAuthAccessToken.Data.AccessToken)
	V1AuthGetRelatedIdRequest.SetOpenId(*OAuthAccessToken.Data.OpenId)
	// sdk调用
	V1AuthGetRelatedId, err := sdkClient.V1AuthGetRelatedId(V1AuthGetRelatedIdRequest)
	if err != nil {
		return nil, err
	}
	// 检查sdk响应错误代码
	if *V1AuthGetRelatedId.ErrNo != 0 {
		return nil, errors.New(*V1AuthGetRelatedId.ErrMsg)
	}

	return &DouYinProvider{SdkClient: sdkClient, OAuthAccessToken: OAuthAccessToken.Data, V1AuthGetRelatedId: V1AuthGetRelatedId.Data}, nil
}

func (p *DouYinProvider) GetProviderId() *string {
	return p.V1AuthGetRelatedId.AlliedId
}

func (p *DouYinProvider) GetUserMeta() (map[string]any, error) {
	sdkRequest := &openApiSdkClient.OauthUserinfoRequest{}
	sdkRequest.SetAccessToken(*p.OAuthAccessToken.AccessToken)
	sdkRequest.SetOpenId(*p.OAuthAccessToken.OpenId)
	// sdk调用
	OauthUserinfo, err := p.SdkClient.OauthUserinfo(sdkRequest)
	if err != nil {
		return nil, err
	}
	// 检查sdk响应错误代码
	if *OauthUserinfo.ErrNo != 0 {
		return nil, errors.New(*OauthUserinfo.ErrMsg)
	}

	data, err := json.Marshal(DouYinUserInfo{OAuthAccessToken: p.OAuthAccessToken, OauthUserinfo: OauthUserinfo.Data})
	if err != nil {
		return nil, err
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result, nil
}

type DouYinUserInfo struct {
	OAuthAccessToken *openApiSdkClient.OauthAccessTokenResponseData
	OauthUserinfo    *openApiSdkClient.OauthUserinfoResponseData
}
