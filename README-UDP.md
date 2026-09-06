# 实验 UDP 资产识别

默认构建：`make -j2 && make test`。扩展构建需要 OpenSSL、Expat、Jansson >= 2.7 和 pkg-config：

```sh
sudo apt-get install libssl-dev libexpat1-dev libjansson-dev pkg-config
make clean
make -j2 WITH_UDP_EXTENSIONS=1 test
```

使用 `--udp-probe-profile experimental` 启用实验目录。新识别结果不表示身份经过认证；不少发现协议没有事务随机数。默认设备发现摘要不包含完整配置；`--rawudp` 是显式原始数据输出选项。

Dahua（UDP37810，仅扩展构建）接受单包、无分片、无二进制尾部的 DHIP JSON 发现响应。型号和序列号必须非空，另需合法 IPv4 或 MAC，至少一项有效；不合格的另一项不用于识别。完整包不超过8192字节，JSON深度不超过16、值不超过256、字符串不超过512字节、键不超过128字节。拒绝重复键、尾随NUL和额外JSON根；session/request ID仅作有界字段，不声称具有随机事务关联。

FINS 型号查询必须配置 `--udp-fins-route 源站,目的站`（各1–254，仅网络0/CPU单元0）。没有明确的内部路由时不发送；不要从公网IP推定站号。

固定返回端口的 profile 应使用相应源端口：HiFly 为48899，Gardasoft发现为30310（目标30311），Gardasoft版本为30312（目标30313）。TFTP实验查询必须是独立UDP69扫描，不接受与其他端口混用。

新增行为需通过 `make test`、`git diff --check` 和对应真实接收路径测试。合成数据只证明解析行为；实际互通、单播可达性和支持的报文变体应分别验证，未经实测的功能继续保持实验状态。

AndroMouse（UDP8888）采用公开作者定义的固定七字节发现配对，仅识别完整 `GOTBACK` 应答，不追加键鼠事件、连接确认或设备信息推断。它没有随机事务号；不支持额外尾字节，也不保证全部版本兼容。
