# libseat - 中南大学图书馆座位预约命令行工具

纯命令行程序，无 GUI。基于纯 Win32 API（WinHTTP + BCrypt + Crypt32），
零外部依赖。校区、楼层、候选座位号全部通过命令行参数指定；
登录凭据本地持久化，避免频繁 CAS 登录触发学校风控。

> **免责声明**：本工具仅供个人学习与研究用途，通过官方网页同一套接口
> 操作本人账号的预约，不含任何绕过学校规则的功能。使用者需遵守学校
> 相关规定，对使用本工具产生的一切后果自行负责。

[MIT License](LICENSE)

## 编译

```
g++ -std=c++17 -O2 -municode -o libseat.exe libseat.cpp -lwinhttp -lbcrypt -lcrypt32
```

## 用法

预约（`-s` 中座位按顺序即为优先级，约到一个即停止）：

```
libseat.exe reserve -u <学号> -p <密码> -c 杏林 -f 3 -s 3208,3209,3210
libseat.exe reserve -u <学号> -s 3211              # 使用缓存凭据 + 默认参数
libseat.exe reserve -u <学号> -d 0                  # 约今天而不是明天
```

查看当前及历史预约（显示预约 ID）：

```
libseat.exe list -u <学号>
```

按预约 ID 取消：

```
libseat.exe cancel -u <学号> -i <预约ID>
```

查看候选座位状态（只读调试）：

```
libseat.exe seats -u <学号> -c 杏林 -f 3 -s 3208,3209,3210
```

## 参数说明

| 参数 | 含义 | 默认值 |
|---|---|---|
| `-u` | 学号（必填） | — |
| `-p` | 统一身份认证密码；仅在没有可用 SSO 缓存时需要（首次运行 / 约每 14 天一次） | — |
| `-d` | `0`=今天，`1`=明天 | `1` |
| `-c` | 校区：名称子串（`杏林`/`潇湘`/`岳麓山`）或 premises ID（`71`） | `杏林` |
| `-f` | 楼层过滤（可选）：数字（`3`）或中文（`三楼`） | 不过滤 |
| `-s` | 候选座位列表，逗号分隔，顺序即优先级 | `3208,3209,3210` |
| `-i` | 预约 ID（仅 cancel 使用） | — |

## 登录凭据缓存（三级认证）

- 位置：`%LOCALAPPDATA%\libseat\token_<学号>.txt`
- 第 1 行 = libzw JWT（服务端有效期约 100 分钟）
  第 2 行 = CAS `CASTGC` cookie（通过 `rememberMe=on` 登录获得，有效期 14 天）
- 启动时的三级顺序：
  1. **JWT 探活** —— 用一次轻量请求（`/v4/member/seat`，limit=1）验证缓存
     的 JWT。有效则直接使用，全程零 CAS 流量。
  2. **SSO 静默刷新** —— JWT 过期但 CASTGC 仍有效时，程序仅凭自己持有的
     CASTGC 访问 CAS 登录地址，通过 302 拿到 service ticket，静默铸出新
     JWT。全程无需密码。
  3. **密码登录** —— 仅当没有可用 CASTGC 时（首次运行或超过 14 天）。
     使用 `rememberMe=on`，新 CASTGC 再次有效 14 天。此级需要 `-p`；
     刷新后的凭据对写回缓存文件。
- 已实测验证的行为：多个 TGT 可并存——程序的 CASTGC 不会使浏览器的
  登录态失效，反之亦然。新 JWT 会吊销旧 JWT（单活 token 策略），但
  浏览器会通过自己的 CAS 重定向自动恢复，不会出现可见的登录异常。
- 删除缓存文件即可强制走一次密码登录。
- 实际效果：触发风控的密码登录从"每次运行"降低到约两周一次。

## 运行时区域解析

无硬编码 ID：`-c` 与 `/v4/space/index` 返回的馆舍列表做匹配
（按 ID 或名称子串），`-f` 把数字映射为楼层名（`3` → `三楼`），
区域列表来自 `/v4/space/pick`，座位来自 `/v4/Space/seat`。
座位号会在匹配校区（含楼层过滤）的所有区域中查找。

## 逆向所得 API 链（2026-09-13 实测验证）

### 认证链

1. `GET https://ca.csu.edu.cn/authserver/login?service=<libzw cas 地址>`
   从隐藏 input 中解析 `pwdEncryptSalt`、`execution`（及 `lt`，如有）。
2. `POST` 同一地址，表单编码：
   `username`、`password`（AES-128-CBC-PKCS7，key=salt，iv=随机 16 字符，
   明文 = 随机 64 字符 + 真实密码，再 base64）、`captcha=`、
   `_eventId=submit`、`cllt=userNameLogin`、`dllt=generalLogin`、`lt`、
   `execution`。成功 → 302 到 `libzw.../v4/login/cas?ticket=ST-...`
3. 跟随重定向（保留 cookie）。第二跳的 302 Location 中包含
   `.../h5/index.html#/cas/?cas=<临时码>` —— 提取该临时码
   （不是 ST ticket；ticket 已被服务端消费）。
4. `POST https://libzw.csu.edu.cn/v4/login/user`，body `{"cas":"<临时码>"}`
   → `data.member.token` = JWT，用作 `Authorization: bearer<token>`
   （"bearer" 和 token 之间没有空格）。

### 业务接口（POST，JSON，带 bearer token）

- `/v4/space/index` `{}` → 馆舍 + 楼层树。
- `/v4/space/pick` `{"premisesIds":"<id>","categoryIds":[],"storeyIds":[...],"boutiqueIds":[],"date":"YYYY-MM-DD"}`
  → 该校区/楼层的区域列表。
- `/v4/Space/map` `{"id":"<区域ID>"}` → `data.date.list[]` 按天，
  其中 `times[0].id` = confirm 所需的时段 segment ID。
- `/v4/Space/seat` `{"id":"<区域ID>","day":"YYYY-MM-DD","label_id":[],"start_time":"07:30","end_time":"22:00","begdate":"","enddate":""}`
  → `data.list[]` 座位：`id`（内部 ID）、`no`（显示座号）、`status`
  （1=空闲，2=已约）。
- `/v4/space/confirm` **加密**请求体。明文：
  `{"seat_id":"<内部ID>","segment":"<segment ID>","day":"YYYY-MM-DD","start_time":"","end_time":""}`
  加密：AES-128-CBC-PKCS7，key = `YYYYMMDD + reverse(YYYYMMDD)`（服务器
  当天日期，16 字节），iv = `ZZWBKJ_ZHIHUAWEI`。发送格式为
  `{"aesjson":"<base64>"}`。响应 `code==0` 即成功。
- `/v4/member/seat` `{"type":"1","page":1,"limit":10}` → 预约历史：
  `id`、`status`（2=预约成功，3=使用中，4=已结束，6=用户取消）、`no`、
  `nameMerge`、`beginTime`、`endTime`。
- `/v4/space/cancel` `{"id":"<预约ID>"}`（明文 JSON，无加密）。

## 注意事项

- 只能预约今天和明天。
- 取消次日的预约须在次日 8:30 前操作。
- 同一时段重复预约会被服务端拒绝
  （"当前用户在该时段已存在座位预约，不可重复预约"）。
- AES key 的日期跟随服务器时钟；跨午夜运行偶发失败，重跑即可。
