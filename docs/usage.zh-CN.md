# cutegdb 使用文档

[English](usage.md) · [← README](../README.zh-CN.md)

本文覆盖日常使用：窗口、快捷键、命令栏、脚本，以及反反调试 / 反反虚拟机插件。

## 1. 打开目标

- **File → Open**（或在命令行传入路径）加载并启动程序。执行会停在*系统断点*（加载器的第一条
  指令），与 x64dbg 完全一致。
- **File → Attach**（Alt+A）附加到正在运行的进程。
- **File → Connect to remote target** 通过 `gdbserver` 或 QEMU 的 gdb stub 进行远程调试。

在系统断点处按 **F9** 会运行到*入口断点*（程序入口点），随后运行到你设置的断点。

## 2. CPU 视图

默认标签页仿照 x64dbg：反汇编（左上）、寄存器（右上）、信息框与参数面板、内存转储与栈
（底部）。反汇编中绘制跳转箭头，变化的寄存器会高亮，信息框解释当前所选指令。

## 3. 快捷键

cutegdb 采用 x64dbg 的默认快捷键，最常用的有：

| 按键 | 功能 |
|---|---|
| F9 | 运行 / 继续 |
| F7 | 单步步入 |
| F8 | 单步步过 |
| Ctrl+F9 | 执行到返回 |
| F2 | 切换断点 |
| F4 | 运行到所选行 |
| Ctrl+G | 跳转到表达式 |
| G | 所选函数的控制流图 |
| X | 查找对所选地址的引用 |
| Ctrl+B | 查找字节模式（支持 `?` 通配） |
| Space | 在所选指令处汇编 |
| ; | 添加注释 |
| : | 添加标签 |
| Ctrl+P | 补丁管理器 |
| Alt+B / Alt+K / Alt+M | 断点 / 调用栈 / 内存映射 |

完整列表定义在 `crates/app/ui/shortcuts.cpp`。

## 4. 命令栏

底部命令栏接受三类输入；右侧下拉框在 **Default** 与 **Python** 之间切换。

- **x64dbg 命令**，会被翻译为 GDB —— 例如 `bp add`、`bph counter,w,4`、`rax=1234`、
  `g`（继续）、`t`/`p`（单步）、`ticnd`/`tocnd`（条件跟踪）。
- **原始 GDB** —— GDB 能识别的一切都会直接透传（`info registers`、
  `-data-evaluate-expression …` 等）。
- **Python** —— 将下拉框切到 Python 后，该行会在 GDB 内嵌解释器中执行
  （`print(gdb.selected_frame().pc())`）。

表达式支持寄存器、符号、`模块.符号`、十六进制/十进制数字，以及 `[地址]` 内存解引用。

## 5. 脚本

**Script** 标签页运行 x64dbg 风格脚本：每行一条命令，`label:` 定义标签，`cmp` 配合条件跳转
（`je`/`jne`/`jl`/…）、`call`/`ret` 以及 `pause`。控制键遵循 x64dbg：**Ctrl+O** 打开、
**Ctrl+L** 加载所编辑文本、**Ctrl+R** 重载、**Ctrl+U** 卸载以便编辑、**Space** 运行、
**Tab** 单步、**Esc** 中止。当前执行行会高亮。

需要更复杂的自动化时，可在命令栏使用 Python，或使用 GDB 的 `source`。

## 6. 跟踪与图

- **Tracing → Trace into / over**（或 `ticnd`/`tocnd`）会记录已执行的指令，直到中断条件成立
  或达到步数上限。**Trace** 标签页列出每条指令及其改变的寄存器，并可导出跟踪结果。
- 在反汇编中按 **G** 构建当前函数的 **Graph（图）**：基本块之间以“跳转成立”（绿）、
  “跳转不成立”（红）与“无条件”（蓝）三种边连接。Ctrl+滚轮缩放；双击在反汇编中跟随某个块。

## 7. 反反调试与反反虚拟机插件

### 使用方法

打开 **Plugins** 菜单。对抗功能分为 **Anti-anti-debug**（反反调试）与 **Anti-anti-VM**
（反反虚拟机）两个子菜单，每项均为可勾选项（悬停可见说明；每个子菜单底部有 *Enable all* /
*Disable all*）。你的选择会被保存，并在每次新进程到达入口点或你附加时自动重新应用——所以只需
设置一次即可。若目标当前处于暂停状态，勾选会立即生效。

**Plugins → Plugin status…** 显示当前生效的对抗功能，以及各自已经化解了多少次检测。

### 工作原理

每个插件会注入一小段 GDB Python 模块，安装“静默断点”——它们修改被调试程序看到的世界并直接
继续执行，从不向界面报告一次停止，因此不会干扰你自己的断点或单步。活动会写入日志
（`[cutegdb-plugin] …`）：

![Log 标签页：反虚拟机 CPUID 示例在启用 CPUID spoof 后全部报告 clean](images/plugins-log.png)

### 各插件

| 插件 | 化解的检测 | 说明 |
|---|---|---|
| **ptrace guard** | 调试器下 `ptrace(PTRACE_TRACEME/ATTACH)` 返回失败；`PTRACE_PEEKUSER` 读取调试寄存器 | 挂钩 libc 的 `ptrace` 封装 |
| **procfs & environment cloak** | `/proc/*/status` 的 TracerPid、跟踪状态、调试器父进程名；`getenv` 读取 `LD_PRELOAD` 等 | 改写 `read()` 结果 |
| **timing normalizer** | 用于检测单步的 `rdtsc`/`rdtscp` 与 `clock_gettime`/`gettimeofday` 时间差 | **尽力而为**：虚拟化时间，目标不再看到真实时间；别处很大的单步延迟仍会消耗真实墙钟时间 |
| **software-breakpoint cloak** | 通过 `/proc/self/mem` 读取自身代码、查找 `0xCC` 的自校验 | **尽力而为**：在此类读取时恢复原始字节；由直接 CPU 读取构造的校验和无法拦截——那种情况应优先使用硬件断点 |
| **CPUID spoof** | hypervisor 标志位（leaf 1）、hypervisor 厂商 leaf（`0x40000000`）与品牌字符串 | 仅限 x86/x86-64 |
| **VM file & device cloak** | DMI 厂商/产品字符串、`/proc/cpuinfo` 的 hypervisor 标志、虚拟机网卡 MAC OUI，以及虚拟机设备节点（`/dev/vboxguest`、`/dev/vmci` 等） | 让虚拟机文件读起来像裸机，让虚拟机设备看起来不存在 |
| **VM syscall cloak** | `uname`、主机名（例如名为 `kali` 的分析机）与上报的内存大小 | 归一化为一台普通工作站 |

### 局限性

- 挂钩针对的是 libc 封装，因此静态链接、在入口点之前直接发起 `syscall`/`cpuid` 的目标可能
  绕过它们。
- 默认不跟随 fork 子进程，因此从子进程发起的检测不在覆盖范围内。
- 两个尽力而为的插件在菜单中标有 ⚠，并会在日志中记录未能完全隐藏的部分。

## 8. 示例

[`examples/`](../examples/) 中每种技术对应一个小程序。构建并运行：

```sh
cd examples && make
./build/anti-vm/cpuid            # 在虚拟机上会打印 DETECTED 行
```

随后在 cutegdb 中打开同一个二进制文件，启用对应插件并按 F9——日志会显示这些检测变为
`clean`。完整对照表见 [`examples/README.md`](../examples/README.md)。

## 9. 测试

```sh
cargo test -p cutegdb-mi -p cutegdb-core -p cutegdb-cmd   # 单元 + 集成（需要 gdb、gcc）
cargo clippy --workspace --all-targets
```

- **无界面冒烟测试**：`QT_QPA_PLATFORM=offscreen cargo run -- --smoke-test out.png <程序>`
  会打开程序、运行到入口断点并对 CPU 标签页截图。
- **实机 GUI 测试**：`scripts/x11-test.sh` 在 X11 显示上驱动一个真实窗口走完整个工作流
  （包括启用一个插件），截图保存在 `target/x11-test/`。它通过 `scripts/xkey.py`（XTEST）
  发送按键，并在屏幕锁定时自动跳过。

反虚拟机集成测试仅在宿主为虚拟机来宾时断言“检测→clean”；在裸机上会跳过并打印提示。

- **截图**：`scripts/screenshots.sh` 会通过在 `anti-vm/cpuid` 示例上启用插件来驱动 cutegdb，
  重新生成本文档中的图片。
