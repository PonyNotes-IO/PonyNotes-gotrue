package provider

import (
	"context"
	"time"

	credential "github.com/bytedance/douyin-openapi-credential-go/client"
	openApiSdkClient "github.com/bytedance/douyin-openapi-sdk-go/client"
	"golang.org/x/oauth2"
)

type DouYinProvider struct {
	SdkClient openApiSdkClient.Client
}

func (p DouYinProvider) AuthCodeURL(s string, option ...oauth2.AuthCodeOption) string {
	return ""
}

func NewDouYinProvider(scopes string) (OAuthProvider, error) {
	// 初始化SDK client
	opt := new(credential.Config).
		SetClientKey("tt******"). // 改成自己的app_id
		SetClientSecret("cbs***") // 改成自己的secret
	sdkClient, err := openApiSdkClient.NewClient(opt)
	if err != nil {
		return nil, err
	}
	return &DouYinProvider{SdkClient: *sdkClient}, nil
}

func (p DouYinProvider) GetUserData(ctx context.Context, token *oauth2.Token) (*UserProvidedData, error) {

	return &UserProvidedData{}, nil
}

func (p DouYinProvider) GetOAuthToken(s string) (*oauth2.Token, error) {
	/* 构建请求参数，该代码示例中只给出部分参数，请用户根据需要自行构建参数值
	   	token:
	   	   1.若用户自行维护token,将用户维护的token赋值给该参数即可
	          2.SDK包中有获取token的函数，请根据接口path在《OpenAPI SDK 总览》文档中查找获取token函数的名字
	            在使用过程中，请注意token互刷问题
	       header:
	          sdk中默认填充content-type请求头，若不需要填充除content-type之外的请求头，删除该参数即可
	*/
	sdkRequest := &openApiSdkClient.OauthAccessTokenRequest{}
	sdkRequest.SetClientKey("eCnIQ8LV0v")
	sdkRequest.SetClientSecret("Fka4nAW19n")
	sdkRequest.SetCode("5hamPsxD6b")
	sdkRequest.SetGrantType("BKuovVPgJ0")
	// sdk调用
	sdkResponse, err := p.SdkClient.OauthAccessToken(sdkRequest)
	if err != nil {
		return nil, err
	}
	// sdkResponse.Data.OpenId
	return &oauth2.Token{
		AccessToken:  *sdkResponse.Data.AccessToken,
		RefreshToken: *sdkResponse.Data.RefreshToken,
		Expiry:       time.Unix(*sdkResponse.Data.ExpiresIn, 0),
	}, nil
}
