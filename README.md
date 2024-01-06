# Mhuo Udp Sniffer
Mhuo系列的Udp抓包器

## 运行环境

### 必需环境
- [winpcap](https://www.winpcap.org/) v4.1.2+


## 数据包结构
### UDP头部
```
D0 9D - 源端口号
5B 05 - 目标端口号
00 6E - 长度
BA 81 - 校验和
```

### KCP头部
```
D1 78 02 00 43 92 E6 96 - conv
51 - cmd
00 - frg
00 01 - wnd
0B 00 00 00 - ts
00 00 00 00 - sn
00 00 00 00 - una
4A 00 00 00 - len
```

### XOR加密数据
```
DA 88 24 70 - 加密魔数
... - 加密内容(包含加密魔数)
```
