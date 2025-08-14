# 阿里云短信服务集成

本文档描述了如何在 GoTrue 中集成和使用阿里云短信服务。

## 功能概述

阿里云短信服务集成支持：
- 发送短信验证码
- 基于阿里云 SMS API 的认证和签名
- 可配置的模板和签名

## 配置

### 环境变量

在您的环境文件中添加以下配置：

```env
# 设置SMS提供商为阿里云
GOTRUE_SMS_PROVIDER="aliyun"

# 阿里云SMS配置
GOTRUE_SMS_ALIYUN_ACCESS_KEY_ID="your_access_key_id"
GOTRUE_SMS_ALIYUN_ACCESS_KEY_SECRET="your_access_key_secret"
GOTRUE_SMS_ALIYUN_SIGN_NAME="your_sign_name"
GOTRUE_SMS_ALIYUN_TEMPLATE_CODE="your_template_code"

# 其他SMS相关配置
GOTRUE_SMS_AUTOCONFIRM="false"
GOTRUE_SMS_MAX_FREQUENCY="5s"
GOTRUE_SMS_OTP_EXP="6000"
GOTRUE_SMS_OTP_LENGTH="6"
```

### 配置参数说明

- `GOTRUE_SMS_ALIYUN_ACCESS_KEY_ID`: 阿里云 Access Key ID
- `GOTRUE_SMS_ALIYUN_ACCESS_KEY_SECRET`: 阿里云 Access Key Secret
- `GOTRUE_SMS_ALIYUN_SIGN_NAME`: 短信签名名称
- `GOTRUE_SMS_ALIYUN_TEMPLATE_CODE`: 短信模板代码

## 阿里云SMS配置要求

### 1. 获取 Access Key

1. 登录阿里云控制台
2. 进入 AccessKey 管理页面
3. 创建 AccessKey，获取 Access Key ID 和 Access Key Secret

### 2. 配置短信签名

1. 进入短信服务控制台
2. 在"短信签名"页面添加签名
3. 等待审核通过后获取签名名称

### 3. 配置短信模板

1. 在短信服务控制台的"短信模板"页面
2. 创建验证码模板，模板内容示例：
   ```
   您的验证码是${code}，有效期为5分钟。
   ```
3. 等待审核通过后获取模板代码

### 模板参数

当前实现会自动将验证码作为 `code` 参数传递给模板：
```json
{
  "code": "123456"
}
```

## API 使用

一旦配置完成，阿里云SMS将自动集成到 GoTrue 的认证流程中：

### 手机号注册/登录

```http
POST /signup
Content-Type: application/json

{
  "phone": "+8613800138000",
  "password": "your_password"
}
```

### 发送短信验证码

```http
POST /otp
Content-Type: application/json

{
  "phone": "+8613800138000"
}
```

### 验证短信验证码

```http
POST /verify
Content-Type: application/json

{
  "type": "sms",
  "phone": "+8613800138000",
  "token": "123456"
}
```

## 错误处理

阿里云SMS集成包含完整的错误处理：

- 配置验证错误
- API 调用错误
- 阿里云服务错误

错误会以标准的 GoTrue 错误格式返回。

## 安全注意事项

1. **保护密钥**: 确保 Access Key Secret 的安全，不要在代码中硬编码
2. **频率限制**: 配置适当的 `GOTRUE_SMS_MAX_FREQUENCY` 以防止滥用
3. **IP白名单**: 在阿里云控制台配置API访问的IP白名单
4. **监控使用**: 定期监控短信发送量和费用

## 测试

运行阿里云SMS提供商的测试：

```bash
go test ./internal/api/sms_provider -run TestAliyun
```

## 故障排除

### 常见问题

1. **签名错误**: 检查 Access Key 是否正确
2. **模板不存在**: 确认模板代码和模板内容匹配
3. **签名不符**: 确认签名名称正确且已审核通过
4. **手机号格式**: 确保手机号格式符合要求（包含国家代码）

### 调试

启用调试日志查看详细错误信息：

```env
GOTRUE_LOG_LEVEL="debug"
```

## 相关文件

- `internal/api/sms_provider/aliyun.go` - 阿里云SMS提供商实现
- `internal/api/sms_provider/aliyun_test.go` - 测试文件
- `internal/conf/configuration.go` - 配置定义
- `internal/api/sms_provider/sms_provider.go` - SMS提供商工厂
