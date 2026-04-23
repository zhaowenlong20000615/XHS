# 手机端 HTTP 转发代理 — 使用文档

**状态**: ✅ 已部署验证通过
**日期**: 2026-04-16

---

## 一句话

手机上跑了一个 HTTP 代理服务 (端口 18888)，电脑发请求时在 header 里指定 `X-Target-URL`，代理用手机的国内网络去请求那个 HTTPS URL，把结果原样返回。

```
电脑 (海外 IP 38.175.x.x)
  │
  │  HTTP POST http://localhost:18888/
  │  Header: X-Target-URL: https://edith.xiaohongshu.com/api/...
  │  Header: shield: XXXX...
  │  Body: {...}
  │
  ▼
adb forward tcp:18888 tcp:18888
  │
  ▼
手机 (国内 IP 123.149.x.x)
  │  PhoneProxy.java (app_process)
  │  → HTTPS GET/POST 到 edith.xiaohongshu.com
  │  ← 200 OK + response body
  │
  ▼
电脑收到原始 response
```

---

## 快速开始

### 1. 启动代理 (每次手机重启后需要执行一次)

```bash
adb forward tcp:18888 tcp:18888
adb shell 'su -c "pkill -f proxy.dex 2>/dev/null; nohup app_process -Djava.class.path=/data/local/tmp/proxy.dex /system/bin PhoneProxy > /data/local/tmp/proxy.log 2>&1 &"'
```

### 2. 验证

```bash
curl -s http://localhost:18888/ -H "X-Target-URL: https://httpbin.org/ip"
# 应返回: {"origin": "123.149.x.x"}  ← 国内 IP
```

### 3. 在代码里使用

```python
import requests

def xhs_request(method, url, headers, body=None):
    """通过手机代理发请求，绕过海外 IP 限制"""
    proxy_headers = dict(headers)
    proxy_headers["X-Target-URL"] = url
    resp = requests.request(
        method,
        "http://localhost:18888/",
        headers=proxy_headers,
        data=body,
    )
    return resp.status_code, resp.text

# 示例
status, body = xhs_request(
    "GET",
    "https://edith.xiaohongshu.com/api/sns/v4/note/user/posted?user_id=69bee48e0000000033039bcc&num=10",
    headers={
        "User-Agent": "com.xingin.xhs/9.19.0",
        "shield": "XYAAAABAAAAAEAAABTAAAAUzUW...",
        "x-mini-gid": "7cb75c2d...",
        "x-mini-s1": "AAUAAAAB...",
        "x-mini-sig": "6eea75d0...",
        "x-mini-mua": "eyJh...",
        "xy-common-params": "fid=&gid=...",
        "xy-platform-info": "platform=android&build=9190807&deviceId=...",
        "xy-direction": "26",
        "xy-scene": "fs=0&point=601",
    },
)
print(status, body[:200])
```

---

## 接口规范

| 项 | 值 |
|---|---|
| **监听地址** | `0.0.0.0:18888` (手机端) |
| **电脑访问** | `http://localhost:18888/` (通过 adb forward) |
| **协议** | 收: HTTP → 发: HTTPS |
| **请求方法** | GET / POST / PUT / DELETE 均支持 |

### 请求格式

```http
POST / HTTP/1.1
Host: localhost:18888
X-Target-URL: https://edith.xiaohongshu.com/api/sns/v2/note
Content-Type: application/json
shield: XYAAAABAAAAAEAAABTAAAAUzUW...
x-mini-gid: 7cb75c2d...

{"title":"test","desc":"hello"}
```

- `X-Target-URL` (必填): 真实目标 URL
- 其余 header 原样转发给目标服务器
- 自动去掉: `Host`、`Accept-Encoding` (强制用 identity 拿明文)
- POST/PUT body 原样转发

### 响应格式

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 1234

{"code":0,"success":true,"data":{...}}
```

- Status code 原样返回
- Body 原样返回 (不压缩)
- 添加 `Access-Control-Allow-Origin: *` (方便浏览器调试)

---

## 文件清单

| 文件 | 位置 | 说明 |
|---|---|---|
| `PhoneProxy.java` | `tools/phone_proxy/PhoneProxy.java` | 源码 (150 行) |
| `classes.dex` | `tools/phone_proxy/classes.dex` | 编译产物 |
| `proxy.dex` | `/data/local/tmp/proxy.dex` (设备) | 运行时 dex |
| `proxy.log` | `/data/local/tmp/proxy.log` (设备) | 运行日志 |

---

## 重新编译 (改代码后)

```bash
cd tools/phone_proxy
javac PhoneProxy.java
d8 --output . PhoneProxy.class
adb push classes.dex /data/local/tmp/proxy.dex
# 重启代理
adb shell 'su -c "pkill -f proxy.dex; nohup app_process -Djava.class.path=/data/local/tmp/proxy.dex /system/bin PhoneProxy > /data/local/tmp/proxy.log 2>&1 &"'
```

---

## 排错

### 代理没响应

```bash
# 检查进程
adb shell 'ps -A | grep proxy'
# 看日志
adb shell 'cat /data/local/tmp/proxy.log'
# 检查 adb forward
adb forward --list
```

### 手机没网

```bash
# 检查时钟 (reboot 会 reset)
adb shell date
adb shell 'su -c "date 041613002026.00"'

# 杀 VPN (Postern/v2ray 会抢路由)
adb shell 'am force-stop com.tunnelworkshop.postern'
adb shell 'am force-stop com.v2ray.ang'

# 验证
adb shell 'ping -c 1 8.8.8.8'
```

### 目标返回 406

不是代理的问题 — 是签名 header 不对。代理只做透传,不改任何 header。检查你的 shield / x-mini-* 签名是否正确。

---

## 验证记录 (2026-04-16)

```
$ curl -s http://localhost:18888/ -H "X-Target-URL: https://httpbin.org/ip"
{
  "origin": "123.149.1.151"
}
```

电脑直连的出口 IP 是 `38.175.103.82` (海外),通过手机代理后变成 `123.149.1.151` (国内)。XHS 服务器不再因 IP 拒绝请求。
