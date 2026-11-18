# GSB Bugfix Task
## 题面
服务跨域配置变更后出现跨域信任漏洞：直接反射Origin请求头、允许携带凭证时通配*、未校验Origin大小写、缺少子域名校验、未限制请求方法；web/cors_middleware.py 是核心，tests/test_cors_policy.py 15个红。要修的是：使用域名白名单而非反射、凭证模式禁用通配符、origin统一小写校验、增加子域名匹配规则、限制允许请求方法。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：漏洞检测与攻防
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：无外部依赖
