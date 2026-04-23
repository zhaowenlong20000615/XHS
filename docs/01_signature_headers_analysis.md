# XHS Signature Headers Analysis

Source: `capture/session2_full_usage_20260411_123810.mitm`  
Total request flows: **399**

## Signature-related Headers

| Header | # endpoints | Example value (truncated) |
|---|---|---|
| `shield` | 25 | `XYAAQABAAAAAEAAABTAAAAUzUWEe0xG1IbD9/c+qCLOlKGmTtFa+lG438PdeFeRKoTlIa5nbRvSJ34qu...` |
| `x-mini-mua` | 27 | `eyJhIjoiRUNGQUFGMDEiLCJjIjo1LCJrIjoiY2M1YjdiZTRlYWExOTJkOGM0MGI5ZmJkMTlkYTQxNjlm...` |
| `x-mini-sig` | 27 | `c2dd5cf569aa87ba2334423dc12e1c6d32cc25a7cb79031b242e6f1f8e11ac09...` |
| `x-mini-s1` | 27 | `AAUAAAAB4vp81xZB5MyL5aR1hQyTTMLeu9nV3XeQDR0hOhMnpPwg4N2TGF4I+SB61IZ5eIdWzeWRFKs8...` |
| `x-mini-gid` | 27 | `7cb84c678fdb5495c7fef9cd674f81d13df3dce94735967b77e3bde4...` |
| `x-legacy-did` | 22 | `aa293284-0e77-319d-9710-5b6b0a03bd9c...` |
| `x-legacy-sid` | 22 | `session.1774780073824545783425...` |
| `x-b3-traceid` | 24 | `f2f29d61ed100f0f...` |
| `x-xray-traceid` | 24 | `ca672ab5cfc2d4dad9b7029238b6115d...` |

## x-mini-mua (base64 JSON + binary tail)

```json
{
  "a": "ECFAAF01",
  "c": 5,
  "k": "cc5b7be4eaa192d8c40b9fbd19da4169feb94ab76231161dc3a0522ce505e57a",
  "p": "a",
  "s": "3264176532895bb568b0507ba7e5ee51927c198a9731791d326352629153aea03e8d283bd5c298ef9736353e1a1c19053c1bdca14e329fde25807af5911ff60f",
  "u": "00000000a5b8432c4477b55337ca062a3476ba1b",
  "v": "2.9.55"
}
```

Binary tail: **788 bytes**, hex:
```
2cf51d4a31257bdbc71404ece85bc53c1490753fa789f1d23d716c6d4e255163829027a6541c616e3ca4e6f404f940a3860815eb6b8c789c238ef3abcd21b12f3a64e639450539b5bc1d8925060306d384c5327dc6773eb344c699b818413bc033f0649d9dea83bae44992c5915a8c301b07423a28b950c8e9194409cba14bb2c5dc5229ed58fda06b0811f70580efc3d3779b5d7d420b6b8c524baf50a022547f57b55320b9ab9c23c1d8fd19704ef2dea786ec40240a8d9047d4371bc68044ea91c57b7d11197e360fd6b81a3c10102c20d389464fa9294a87890a0440c5d466993ce8969fc1a2407e00dcfc51610b806f08fc06a7d46ba671b057a61af9b6a51960769cdc6a77337cb2f4648cfba59479c5f411b05e36a1e0d1841ab6f1d2b360f9d49dee9a49909f7033d14ac2b71e7f5a69a5df5f9e46cf0b64045bb82f3b9f8d9e68d030cb73b707cf742c4bb1422ad1fd806e5703c5a5ec13ddb0ff2b167495430999aa9a6ae94a0e43b643d48396b07ddc4da7b43023b75ef1cb582d756a83ef9f74a88d3f6f847497e0f65838209069ba08298ca9d3289ae39a8de539a0ce940a5f081a6d5d99cc40b5e03138ac8f0b227ecee0fa9af1c0a168171f52ee4b08a5de9e42efe00d6c93ce763ca918d691a699e25038c2e504e9a544b6150fa275a3076ec51e40ec89d0a06a0860ad691a9e1b6e9ed4c92e90c8cc2f32e971b40d8c583bb7d152f98d8979c86e5a7a78efef278baf5d2889f0fda666cc832086d8247b9645e12f98981c1b62ca757693d7063260654181bc973bcdb495cd01f24d817501b7d115c5d99d210a78902e94843122b714c6abcd3d008da4bab63b45f8cfec66528d2e5eadf37284c86aeae778514e5ec4e4b0636d360597aa92eb312843d0d7d2f3387872610f446fd2549c926672f541d7d6c1ea02a0d2edf8376d179e752b987924989e75ce4ddcb29c9dbfb33371c2463823a1bae922e9dee907a2194011191ed1b383373c429b087f6b0ad77b4770c58f9f25245d12a0b5e637703f3318d4c84ee49c7aad89e08408459afd90f0e5b89dd0b1b2077e467d3485ba122e80aa63284633860e44c0a6336db9
```

### MUA field meaning (reversed)

- `a` = device identifier hash (hex)
- `c` = constant (version/cipher id, =5)
- `k` = per-device key (likely HMAC key source, 64 hex chars)
- `p` = platform ("a"=android)
- `s` = session token / device signature (128 hex)
- `u` = Install-UUID (XHS device id)
- `v` = app version
- trailing binary = HMAC/signature over the JSON (100 bytes, likely SHA-256 + padding/nonce)

## shield header (base64 binary)

- Length: **100 bytes**
- Magic: `5d800040` (likely version/type header)
- Full hex:
```
5d800040004000000010000005300000053351611ed311b521b0fdfdcfaa08b3a5286993b456be946e37f0f75e15e44aa139486b99db46f489df8aae758cfc32bd5997ed8a533100c4b4363da64eaf4df79348fb7f8b624ba0260af7ab2c9b2d73c5dba1
```

## x-mini-s1 (base64 binary)

- Length: **62 bytes**
- Magic: `00050000`
- Full hex: `000500000001e2fa7cd71641e4cc8be5a475850c934cc2debbd9d5dd77900d1d213a1327a4fc20e0dd93185e08f9207ad48679788756cde59114ab3cbc7c`

## x-mini-sig

- Length: **64 chars** = 32 bytes → matches SHA-256 output
- Example: `c2dd5cf569aa87ba2334423dc12e1c6d32cc25a7cb79031b242e6f1f8e11ac09`

## Endpoints requiring signature (25+ endpoints)

- `/api/capa/configlist` (shield+mini)
- `/api/httpdns/prefetch` (shield)
- `/api/im/v2/messages/offline` (shield+mini)
- `/api/model_portrait/detect_items` (shield)
- `/api/model_portrait/model_score` (shield)
- `/api/nike/v4/update/check/andrshipinfo` (shield+mini)
- `/api/push/get_gesture_guidance_config` (shield+mini)
- `/api/push/query_badge_exp` (shield+mini)
- `/api/sns/badge/update_badge` (shield+mini)
- `/api/sns/reach/msg/query` (shield+mini)
- `/api/sns/v1/account/phone-binding-dialog` (shield+mini)
- `/api/sns/v1/content/navigator` (shield+mini)
- `/api/sns/v1/followings/reddot` (shield+mini)
- `/api/sns/v1/paddles/pull_configs` (shield+mini)
- `/api/sns/v1/paddles/pull_shanks` (shield+mini)
- `/api/sns/v1/system_service/config` (shield+mini)
- `/api/sns/v1/tag/reobpage` (shield+mini)
- `/api/sns/v1/user/signoff/flow` (shield+mini)
- `/api/sns/v2/system_service/splash_async_optimization` (shield+mini)
- `/api/sns/v2/user/account_info/anomalies` (shield+mini)
- `/api/sns/v2/user/teenager/status` (shield+mini)
- `/api/sns/v6/homefeed` (shield+mini)
- `/api/sns/v6/homefeed/categories` (shield+mini)
- `/api/sns/v6/message/detect` (shield+mini)
- `/api/usergrowth/mallbanner` (shield+mini)
- `/api/v1/cfg/android` (mini)
- `/api/v1/dvf/gch/android` (mini)
- `/api/v1/prb/android` (mini)
- `/api/v1/profile/android` (mini)
- `/api/v1/register/android` (mini)
