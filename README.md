# P4项目：多模态可编程网络转发

## 项目概述
本项目基于P4语言实现了一个支持多协议转发的可编程网络系统，展示了P4编程的强大灵活性。通过BMv2软件交换机和Mininet仿真环境，实现以下功能：

- **IPv4/IPv6双模态转发**：传统路由协议支持
- **Yequdesu自定义隧道协议**：EtherType 0x1313的专用隧道
- **VXLAN虚拟网络**：UDP端口4789的虚拟网络覆盖
- **源路由**：显式路径控制（框架已实现，规则待配置）

所有模态都支持双向通信，且通过智能解析和匹配机制实现互不冲突的并存。项目包含完整的P4程序、Python控制器、测试工具和自动化验证脚本。

## 网络拓扑
- 主机：h1 (10.0.1.1/24, 2001:db8:1::1/64), h2 (10.0.2.2/24, 2001:db8:1::2/64)
- 交换机：s1, s2, s11, s12, s21, s22, s31, s32, s41, s42
- IPv4路径：h1 → s1 → s11 → s12 → s2 → h2
- IPv6路径：h1 → s1 → s21 → s22 → s2 → h2
- Yequdesu隧道路径：h1 → s1 → s31 → s32 → s2 → h2
- VXLAN路径：h1 → s1 → s41 → s42 → s2 → h2

## 功能特性

### Level 1: IPv4单模态网络
实现基本的IPv4转发功能：
- 移除原有的myTunnel头部，使用直接路由转发
- s11、s12作为纯转发节点，处理IPv4包
- 通过P4Runtime动态配置转发规则
- 支持ARP请求响应和校验和计算

验证方法：使用pingall测试连通性，通过tcpdump抓包验证包转发。

### Level 2: IPv4/IPv6双模态网络
在单模态基础上扩展IPv6支持：
- 新增IPv6头部解析和转发逻辑
- IPv6使用独立的路径(s21-s22)，实现流量分离
- s1和s2支持双栈转发，同时处理IPv4和IPv6
- IPv6包进行hop limit递减处理

验证方法：使用Scapy构造IPv6包测试，通过抓包确认IPv6包转发。

### Level 3: 多模态网络扩展
进一步扩展网络功能：
- 集成源路由(srcRoute)头部，支持显式路径控制
- 新增Yequdesu自定义隧道协议，支持IPv4封装
- 新增VXLAN虚拟网络覆盖，支持虚拟网络隔离
- 实现多种转发模态并存（传统路由、Yequdesu隧道、VXLAN、源路由）
- 支持双向通信和复杂路由策略
- 为未来网络协议扩展提供基础架构

### 核心技术亮点
- **多协议并存**：智能头部解析，支持5种以上协议类型
- **冲突解决**：通过专用IP地址和协议标识避免路由冲突
- **动态配置**：P4Runtime控制器实现规则热更新
- **双向通信**：所有模态都支持完整双向数据传输
- **可扩展性**：模块化设计，便于添加新的网络协议

### Yequdesu隧道协议
- **协议标识**：EtherType 0x1313
- **头部结构**：proto_id (16位) + dst_id (16位)
- **转发路径**：h1 → s1 → s31 → s32 → s2 → h2
- **封装内容**：IPv4数据包
- **目的IP**：10.0.2.4 (去程), 10.0.1.3 (回程)
- **使用方法**：
  ```bash
  # 发送Yequdesu隧道包
  python3 send_tunnel.py 10.0.2.4 "Hello Tunnel"

  # 接收Yequdesu包
  python3 receive_tunnel.py
  ```

### VXLAN虚拟网络
- **协议**：基于UDP的虚拟网络覆盖
- **端口**：UDP 4789
- **VNI**：100 (去程), 101 (回程)
- **转发路径**：h1 → s1 → s41 → s42 → s2 → h2
- **使用方法**：
  ```bash
  # 发送VXLAN包
  python3 send_vxlan.py 10.0.2.2 "Hello VXLAN"

  # 接收VXLAN包
  python3 receive_vxlan.py
  ## 模态配置说明
  
  ### IPv4常规路由
  - **目的IP**：10.0.2.2 (去程), 10.0.1.1 (回程)
  - **路径**：h1 → s1 → s11 → s12 → s2 → h2
  - **特点**：标准IPv4转发，不封装
  
  ### IPv6常规路由
  - **目的IP**：2001:db8:1::2 (去程), 2001:db8:1::1 (回程)
  - **路径**：h1 → s1 → s21 → s22 → s2 → h2
  - **特点**：标准IPv6转发，包含hop limit处理
  
  ### Yequdesu隧道
  - **目的IP**：10.0.2.4 (去程), 10.0.1.3 (回程)
  - **路径**：h1 → s1 → s31 → s32 → s2 → h2
  - **特点**：自定义隧道协议，EtherType 0x1313
  - **解决冲突**：使用专用IP地址，避免与IPv4路由冲突
  
  ### VXLAN虚拟网络
  - **目的IP**：10.0.2.2 (去程), 10.0.1.1 (回程)
  - **路径**：h1 → s1 → s41 → s42 → s2 → h2
  - **特点**：UDP封装，端口4789，支持VNI隔离
  - **VNI**：100 (去程), 101 (回程)
  
  ### 源路由 (框架已实现)
  - **特点**：显式路径控制，支持多跳路由
  - **状态**：P4代码支持，控制器中可配置具体规则
  - **使用方法**：通过`send_src.py`发送源路由包

  ## 注意事项
  - 所有模态都支持双向通信
  - Yequdesu隧道使用专用IP地址避免与IPv4路由冲突
  - VXLAN和IPv4可以共享相同目的IP（通过不同匹配条件区分）
  - 建议使用自动化测试脚本进行完整的功能验证
  - 源路由功能已实现但未在控制器中配置，可根据需要添加规则

## 技术实现
- **P4程序** (`basic.p4`)：定义多协议解析器、转发动作和匹配表，支持多模态并存
  - 多协议头部解析（Ethernet, IPv4, IPv6, ARP, UDP, VXLAN, Yequdesu, SrcRoute）
  - 智能转发逻辑，支持不同模态的冲突解决
  - 校验和计算和验证
  - Hop Limit/TTL递减处理
- **控制器** (`controller.py`)：基于P4Runtime的Python控制器，动态规则部署
  - 支持10个交换机（s1-s2, s11-s12, s21-s22, s31-s32, s41-s42）的规则配置
  - 多模态路由表管理（IPv4/IPv6转发、隧道封装/解封装、VXLAN处理）
  - ARP响应规则部署
  - 规则冲突解决机制
- **测试工具**：
  - `send.py`：统一发送接口，支持IPv4/IPv6/Yequdesu隧道
  - `receive.py`：统一接收接口，支持所有协议类型
  - `send_ipv4.py`：IPv4包发送
  - `receive_ipv4.py`：IPv4包接收
  - `send_ipv6.py`：IPv6包发送
  - `receive_ipv6.py`：IPv6包接收
  - `send_src.py`：源路由包发送
  - `receive_src.py`：源路由包接收
  - `send_tunnel.py`：Yequdesu隧道包发送
  - `receive_tunnel.py`：Yequdesu隧道包接收
  - `send_vxlan.py`：VXLAN包发送
  - `receive_vxlan.py`：VXLAN包接收
  - `test/h1toh2test-send.py`：h1到h2的自动化测试发送脚本
  - `test/h1toh2test-rece.py`：h1到h2的自动化测试接收脚本
  - `test/h2toh1test-send.py`：h2到h1的自动化测试发送脚本
  - `test/h2toh1test-rece.py`：h2到h1的自动化测试接收脚本
- **网络拓扑** (`topology.json`)：Mininet网络拓扑定义
  - 双主机网络（h1: 10.0.1.1/24, h2: 10.0.2.2/24）
  - 10个P4交换机，支持多路径转发
  - IPv4/IPv6双栈配置
- **构建系统** (`Makefile`)：基于BMv2的编译和运行环境
- **参考实现** (`ref/`)：包含多个P4项目示例
  - `basic_tunnel/`：基础隧道实现
  - `homework3/`：负载均衡示例
  - `ipv6_forward/`：IPv6转发实现
  - `p4runtime/`：高级隧道和P4Runtime示例
  - `source_routing/`：源路由实现
  - `vxlan/`：VXLAN虚拟网络（在其他目录中）
- **日志和抓包** (`logs/`, `pcaps/`)：运行时日志和网络流量捕获
- **工具库** (`utils/`)：P4开发辅助工具和LaTeX速查表

## 使用方法

### 1. 环境准备
确保系统已安装：
- P4编译器 (p4c)
- BMv2软件交换机 (simple_switch_grpc)
- Mininet网络仿真器
- Python 3.x 和相关依赖

### 2. 编译和运行
```bash
# 清理旧的编译文件
make clean

# 编译P4程序
make

# 启动控制器（在新终端中运行）
python3 controller.py
```

### 3. 启动Mininet网络
```bash
# 在另一个终端中启动Mininet拓扑
make mininet

# 在Mininet CLI中启动xterm终端
mininet> xterm h1 h2
```

### 4. 测试不同模态
在h1的xterm中发送，在h2的xterm中接收：

```bash
# IPv4转发
python3 send.py --ip 10.0.2.2 --message "IPv4 Hello"

# IPv6转发
python3 send_ipv6.py 2001:db8:1::2 "IPv6 Hello"

# Yequdesu隧道 (使用专用IP地址避免冲突)
python3 send_tunnel.py 10.0.2.4 "Tunnel Hello"

# VXLAN虚拟网络
python3 send_vxlan.py 10.0.2.2 "VXLAN Hello"

# 源路由
python3 send_src.py 10.0.2.2 "Source Route Hello"
```

### 5. 自动化双向测试
```bash
# h1到h2测试 (在h1和h2的xterm中分别运行)
python3 test/h1toh2test-send.py  # 在h1运行
python3 test/h1toh2test-rece.py   # 在h2运行

# h2到h1测试 (在h1和h2的xterm中分别运行)
python3 test/h2toh1test-send.py  # 在h2运行
python3 test/h2toh1test-rece.py   # 在h1运行
```

### 6. 接收测试
```bash
# 接收所有类型包
python3 receive.py --all

# 只接收特定类型
python3 receive.py --ipv4
python3 receive.py --ipv6
python3 receive_tunnel.py    # Yequdesu隧道
python3 receive_vxlan.py     # VXLAN
python3 receive_src.py       # 源路由
```

### 7. 调试和监控
```bash
# 查看交换机日志
tail -f logs/s1.log

# 抓包分析
tcpdump -i s1-eth1 -w capture.pcap

# 使用自动化测试脚本验证所有模态
python3 test/h1toh2test-send.py & python3 test/h1toh2test-rece.py
```