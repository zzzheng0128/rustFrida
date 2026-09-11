# Git 分支、子模块和多人开发流程

这篇文档记录当前仓库的协作流程：先把已有修复合进 `master`，再让新功能和 P5
适配各自走独立分支。多人在同一台电脑开发时，每个人使用自己的 clone 目录，不在同一
个工作区轮流切分支。

## 1. 合并本地修复分支

本地 `fix/java-native-deadlock` 是已经完成的修复分支。先推到自己的远端，再通过 PR
合进主分支。

```bash
cd /Users/freeman/project/douyin/rustFrida

git push -u origin fix/java-native-deadlock
```

创建 PR：

```bash
gh pr create \
  --repo zzzheng0128/rustFrida \
  --base master \
  --head fix/java-native-deadlock \
  --title "fix: Java/native deadlock and stack handling" \
  --body "合并 Java/native deadlock 修复及相关 stack 处理调整。"
```

确认 PR 内容后合并：

```bash
gh pr merge fix/java-native-deadlock \
  --repo zzzheng0128/rustFrida \
  --merge
```

合并后，把本地 `master` 快进到远端最新。这个命令不会切换当前工作区：

```bash
git fetch origin master:master
```

确认修复已经合进 `master` 后，本地老分支可以保留；如果确定不再需要，也可以删除：

```bash
git branch -d fix/java-native-deadlock
```

## 2. 推送当前新功能分支

当前新功能分支例如：

```bash
feat/trace-and-templates
```

这个分支包含主仓库改动，也包含子模块或独立仓库里的改动。推外层仓库之前，要先把
子仓库的提交推到你有权限的远端，否则别人 clone 时会拿不到子模块 commit。

### 2.1 Fork 上游子仓库

显式指定仓库时，`gh repo fork` 不要带 `--remote=false`：

```bash
gh repo fork bellard/quickjs --clone=false
gh repo fork bmax121/KernelPatch --clone=false
```

### 2.2 QuickJS 子模块

`quickjs-hook/quickjs-src` 是外层仓库的 Git 子模块。如果里面有本次功能需要的提交，
先在子模块里提交并推送，然后外层仓库记录新的子模块指针。

```bash
cd /Users/freeman/project/douyin/rustFrida

git submodule set-url quickjs-hook/quickjs-src https://github.com/zzzheng0128/quickjs.git
git -C quickjs-hook/quickjs-src push -u origin feat/trace-and-templates
```

如果后续别人 clone 后发现子模块 URL 没同步，执行：

```bash
git submodule sync --recursive
git submodule update --init --recursive
```

### 2.3 mkpms 独立仓库和 KernelPatch 子模块

`mkpms/` 是另一个独立 Git 仓库，不是外层仓库的普通目录。外层执行 `git add mkpms`
不会保存 `mkpms/` 里面的源码修改。

`mkpms/.kp` 又是 `mkpms` 内部的 KernelPatch 子模块。顺序是：

1. 先推 `mkpms/.kp` 的 KernelPatch 分支。
2. 再在 `mkpms` 里提交新的 `.kp` 指针和 `.gitmodules`。
3. 最后推 `mkpms` 自己。

```bash
cd /Users/freeman/project/douyin/rustFrida

git -C mkpms submodule set-url .kp https://github.com/zzzheng0128/KernelPatch.git
git -C mkpms/.kp push -u origin feat/trace-and-templates

git -C mkpms add .gitmodules
git -C mkpms commit -m "chore: use personal KernelPatch fork"
git -C mkpms push -u origin mkpm-merged
```

如果希望 `mkpms/` 出现在 rustFrida 的 GitHub 文件列表里，需要把它注册成外层仓库的
子模块。它会显示成一个可点击的子模块目录，指向 `zzzheng0128/mkpms` 的某个 commit。

```bash
cd /Users/freeman/project/douyin/rustFrida

git submodule add -b mkpm-merged https://github.com/zzzheng0128/mkpms.git mkpms
git add .gitmodules mkpms
git commit -m "chore: add mkpms submodule"
git push
```

如果 `git submodule add` 提示 `mkpms` 已经存在，可以先确认它里面没有未提交修改：

```bash
git -C mkpms status --short --branch
```

确认干净后，改用下面这个注册已有目录：

```bash
git config -f .gitmodules submodule.mkpms.path mkpms
git config -f .gitmodules submodule.mkpms.url https://github.com/zzzheng0128/mkpms.git
git config -f .gitmodules submodule.mkpms.branch mkpm-merged
git add .gitmodules mkpms
git commit -m "chore: add mkpms submodule"
git push
```

### 2.4 外层仓库

子仓库都推完后，再提交外层仓库的子模块 URL 和新功能分支。

```bash
cd /Users/freeman/project/douyin/rustFrida

git add .gitmodules
git commit -m "chore: use personal QuickJS fork"
git push -u origin feat/trace-and-templates
```

如果任意一步报错，先停在当前步骤排查，不要继续推父仓库。父仓库记录的是子模块
commit 指针；子模块 commit 没推上去，别人就取不到完整代码。

## 3. P5 适配人员如何独立开发

推荐每个开发者单独 clone 一个目录。例如主开发目录是：

```text
/Users/freeman/project/douyin/rustFrida
```

P5 开发者使用另一个目录：

```text
~/project/douyin/rustFrida-p5
```

### 3.1 基于 master 开发

如果 P5 只需要已经合进 `master` 的修复，从 `master` 开分支：

```bash
mkdir -p ~/project/douyin
cd ~/project/douyin

git clone --recurse-submodules \
  https://github.com/zzzheng0128/rustFrida.git rustFrida-p5

cd rustFrida-p5
git switch -c feat/p5-support
```

开发完成后提交：

```bash
git status
git diff

git add -A -- . ':(exclude)mkpms' ':(exclude)dist'
git diff --cached --stat
git diff --cached --check

git commit -m "feat: support Pixel 5"
git push -u origin feat/p5-support
```

创建 PR 到 `master`：

```bash
gh pr create \
  --repo zzzheng0128/rustFrida \
  --base master \
  --head feat/p5-support \
  --title "feat: support Pixel 5" \
  --web
```

### 3.2 基于未合并的新功能分支开发

如果 P5 需要依赖 `feat/trace-and-templates`，先确认该分支以及相关子模块 commit 都已经
推上远端。然后在独立 clone 里基于该分支开 P5 分支：

```bash
cd ~/project/douyin/rustFrida-p5

git fetch origin
git switch --no-track -c feat/p5-support origin/feat/trace-and-templates

git submodule sync --recursive
git submodule update --init --recursive
```

如果本地已经存在 `feat/p5-support`，不要重复 `-c` 创建。先切过去并合并基线：

```bash
git switch feat/p5-support
git fetch origin
git merge origin/feat/trace-and-templates

git submodule sync --recursive
git submodule update --init --recursive
```

这种情况下，P5 的 PR 先指向 `feat/trace-and-templates`：

```bash
gh pr create \
  --repo zzzheng0128/rustFrida \
  --base feat/trace-and-templates \
  --head feat/p5-support \
  --title "feat: support Pixel 5" \
  --web
```

等 `feat/trace-and-templates` 合进 `master` 时，P5 改动再一起进入主线。

## 4. P5 开发期间同步上游

如果 P5 分支基于 `master`：

```bash
cd ~/project/douyin/rustFrida-p5

git fetch origin
git merge origin/master

git submodule sync --recursive
git submodule update --init --recursive
```

如果 P5 分支基于 `feat/trace-and-templates`：

```bash
cd ~/project/douyin/rustFrida-p5

git fetch origin
git merge origin/feat/trace-and-templates

git submodule sync --recursive
git submodule update --init --recursive
```

冲突只会出现在 P5 开发者自己的 clone 目录里，不会影响其他人的工作区。

## 5. 同一台电脑多人开发注意事项

每个开发者应该使用自己的目录和自己的分支：

```text
rustFrida/       当前主开发目录
rustFrida-p5/    P5 适配目录
```

每个 clone 可以设置自己的提交署名：

```bash
git config --local user.name "开发者名字"
git config --local user.email "开发者邮箱"
```

署名不等于 GitHub 登录认证。执行 `git push` 前检查当前 GitHub CLI 登录账号：

```bash
gh auth status
```

如果同一台电脑上有多个 GitHub 账号，最好使用不同 macOS 用户账户，或者明确配置各自的
SSH key / credential，避免把提交推到错误账号。

同一台电脑或同一台设备并行调试时，还要注意这些共享资源：

- 不要在同一个 clone 目录里轮流切分支开发。
- 不要共用同一个未隔离的 `CARGO_TARGET_DIR`。
- adb 设备相同时，`/data/local/tmp/rustfrida` 等设备端路径会互相覆盖。
- 多设备调试时用 `ANDROID_SERIAL`、`adb -s` 或脚本支持的 `DEVICE_SERIAL` 指定设备。
- host 端口转发是全局资源；多人并行时使用不同端口。
- `dist/` 是构建产物，通常不提交，除非本次发布明确需要纳入。

## 6. 分支关系速查

修复先进主线：

```text
master
  ↑
fix/java-native-deadlock
```

P5 只依赖主线修复：

```text
master
  ↑
feat/p5-support
```

P5 依赖未合并的新功能：

```text
master
  ↑
feat/trace-and-templates
  ↑
feat/p5-support
```
