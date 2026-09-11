# rustFrida 文档入口

日常使用、编译、demo 菜单、KPM 判定标准、错误排查，以及 LSPosed/stackplz 对比，
统一看根目录的 [`使用文档.md`](使用文档.md)。它是新用户唯一需要通读的文档。

```bash
cd /Users/freeman/project/douyin/rustFrida
bash examples/rustfrida-compat-app/build_demo.sh
CARGO_TARGET_DIR=rustfrida_target bash .build-android.sh rust_frida
RUN_SECS=60 BUILD_RF=0 bash examples/rustfrida-compat-app/run_demo_spawn.sh 0
```

按目标选择模板：

- [`examples/rustfrida-compat-app/README.md`](examples/rustfrida-compat-app/README.md)：兼容性 demo 的代码结构和实验背景；
- [`examples/templates/README.md`](examples/templates/README.md)：可复制的 JS 模板；
- [`mkpms/DEMO_GUIDE.md`](mkpms/DEMO_GUIDE.md)：KPM 独立 demo 的源码索引；
- [`mkpms/kpms/mkpm/README.md`](mkpms/kpms/mkpm/README.md)：合并 KPM 的编译约束和完整 ctl 命令；
- [`doc/git-branch-submodule-workflow.md`](doc/git-branch-submodule-workflow.md)：分支合并、子模块推送和 P5 独立开发流程；
- `doc/`：实现推导、历史故障和设计记录，只在需要深入查证时阅读；
- `runs/`：设备实验产物，不作为文档入口，也不应把凭据和未脱敏日志提交到公开仓库。

根目录的历史 `test_*`、`probe_*` 和专项报告继续保留，便于回归，不需要作为新手入口。
