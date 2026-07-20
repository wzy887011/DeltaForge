# DeltaForge v3

三角洲行动云手机过检 + 跑刀插件。

## 结构

```
DeltaForge/
├── cloud-agent/
│   ├── native/           # C 过检核心 (forge.c + libforgehook.so)
│   ├── magisk/           # Magisk 模块 (开机自启)
│   └── forge-control.sh  # 一键部署脚本
├── runner/               # Python 跑刀引擎
│   └── config/           # 路线/配置
└── phone-app/            # Android 控制面板 (WIP)
```

## 云手机部署

```bash
# 安装 git 并克隆
pkg install -y git clang
git clone https://github.com/wzy887011/DeltaForge.git
cd DeltaForge/cloud-agent/native

# 编译
make

# 部署并启动 (需 root)
su -c "cp forge /data/local/tmp/ && cp libforgehook.so /data/local/tmp/ && chmod 755 /data/local/tmp/forge"
su -c "sh ../../cloud-agent/forge-control.sh"
```

## 版本

- v3: 当前稳定版 (108处内存补丁 + 32项属性伪装 + 文件清理 + iptables阻断)
