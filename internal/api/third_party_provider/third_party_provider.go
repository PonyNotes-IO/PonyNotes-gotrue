package third_party_provider

type ThirdPartyProvider interface {
	// GetProviderId 获取提供者唯一id
	GetProviderId() *string
	// GetUserMeta 获取用户信息
	GetUserMeta() (map[string]any, error)
}
