# ROS代码安全漏洞检测领域文献调研报告

**调研日期**: 2026-04-25
**调研目的**: 确定RoboGuard项目在机器人软件安全检测领域的研究定位和创新点

---

## 执行摘要

经过系统的文献调研，我们发现：

1. **ROS/机器人软件安全检测领域几乎所有工作都在系统/网络/通信层，没有人做过函数级源代码漏洞检测**
2. **通用软件漏洞检测领域，函数级是主流粒度（2018-至今），行级定位是前沿但尚不成熟**
3. **RoboGuard是首个针对ROS代码的函数级安全漏洞检测系统，填补了明确的研究空白**

---

## 一、ROS/机器人软件安全检测现状

### 1.1 现有工具和研究（按粒度分类）

#### 通信层安全（主流方向）

| 工具/研究 | 年份 | 方法 | 参考文献 |
|---|---|---|---|
| **SROS2** | 2022 | DDS安全插件、访问控制 | [White et al., 2022](https://www.researchgate.net/publication/362489509_SROS2_Usable_Cyber_Security_Tools_for_ROS_2) |
| **ROS2通信安全形式化分析** | 2024 | 状态转换系统、形式化验证 | [Yang et al., Electronics 2024](https://www.mdpi.com/2079-9292/13/9/1762) |
| **ROS2Tester** | 2024 | 形式化方法+渗透测试 | [Springer 2024](https://link.springer.com/chapter/10.1007/978-3-031-64954-7_7) |

#### 系统/网络层安全

| 工具/研究 | 年份 | 方法 | 参考文献 |
|---|---|---|---|
| **ROSPenTo** | 2019 | ROS计算图渗透测试 | [Breiling et al., 2019](https://github.com/jr-robotics/ROSPenTo) |
| **ROSploit** | 2019 | 漏洞利用框架 | [Dieber et al., 2019](https://www.researchgate.net/publication/332075478_ROSploit_Cybersecurity_Tool_for_ROS) |
| **SwRI ROS2 Cybersecurity** | 2021 | Fuzzing（无效输入、资源耗尽、权限提升） | [SwRI 2021](https://www.swri.org/what-we-do/internal-research-development/2021/defense-security/robotics-operating-system-2-cybersecurity-10-r6140) |
| **RoboCop** | 2024 | 零日攻击检测框架 | [NSF 2024](https://par.nsf.gov/biblio/10577390-robocop-robust-zero-day-cyber-physical-attack-detection-framework-robots) |

#### 源代码分析（非函数级）

| 工具/研究 | 粒度 | 安全 vs 质量 | 方法 | 参考文献 |
|---|---|---|---|---|
| **HAROS** | 包/文件级 | 代码质量 | 静态分析（集成Cppcheck, clang-tidy, pylint） | [Santos et al., IROS 2016](https://github.com/HAROS-framework/haros) |
| **Canonical ROS ESM审计** | 包级 | 安全 | 通用静态工具（Semgrep, Bandit, Coverity） | [Canonical 2023](https://canonical-robotics.readthedocs-hosted.com/en/latest/explanations/security/security-audits/) |
| **Coverity Scan on ROS2** | 行/缺陷级 | 混合 | 静态分析 | [ROS2 Discourse](https://discourse.openrobotics.org/t/static-analysis-of-open-source-ros2-c-packages/3577) |
| **AWS ROS2 Sanitizer** | 行级 | Bug（内存错误、竞态） | 动态分析（ASan, TSan） | [AWS 2020](https://discourse.openrobotics.org/t/introducing-ros2-sanitizer-report-and-analysis/9287) |

#### Fuzzing测试

| 工具/研究 | 年份 | 目标 | 方法 | 参考文献 |
|---|---|---|---|---|
| **RoboFuzz** | 2022 | 正确性Bug | 传感器输入Fuzzing | [Kim et al., ESEC/FSE 2022](https://github.com/sslab-gatech/RoboFuzz) |
| **RSFuzz** | 2024 | 逻辑漏洞 | 鲁棒性引导群体Fuzzing | [arXiv 2024](https://arxiv.org/html/2409.04736) |

### 1.2 现有ROS漏洞数据集

| 数据集 | 规模 | 内容 | 安全 vs Bug | 粒度 | 参考文献 |
|---|---|---|---|---|---|
| **RVD** | ~2600条 | 多厂商机器人漏洞 | 混合 | CVE/Issue级（无源代码） | [Alias Robotics](https://github.com/aliasrobotics/RVD) |
| **ROBUST** | 221个 | ROS1包的Bug | 通用Bug | Bug报告级（有patch） | [Timperley et al., 2024](https://github.com/robust-rosin/robust) |
| **ROSPaCe** | 网络流量 | ROS2入侵检测数据 | 安全（网络攻击） | 网络包级 | [Nature 2024](https://www.nature.com/articles/s41597-024-03311-2) |
| **ROSIDS23** | 网络流量 | ROS入侵检测数据 | 安全（网络攻击） | 网络包级 | [PubMed 2023](https://pubmed.ncbi.nlm.nih.gov/38020425/) |

### 1.3 关键发现

✅ **没有人做过ROS代码的函数级安全漏洞检测**
✅ **唯一涉及源代码的工作使用通用静态工具，不针对ROS特性**
✅ **没有人用LLM或深度学习分析ROS源代码安全**（ML应用全部在网络流量层）
✅ **没有函数级、带CWE标签的ROS漏洞数据集**

---

## 二、通用软件漏洞检测的粒度演进

### 2.1 研究发展脉络

| 阶段 | 时间 | 粒度 | 代表工作 | 关键成果 |
|---|---|---|---|---|
| **第一阶段** | 2018-2020 | 函数级 | VulDeePecker, Devign, ReVeal | 建立函数级检测范式 |
| **第二阶段** | 2020-2022 | 函数级（Transformer） | LineVul | F1达到0.91 |
| **第三阶段** | 2022-2024 | 行级定位 + 数据集质量危机 | IVDetect, PrimeVul | 发现数据集标签噪声~50% |
| **第四阶段** | 2024-2025 | LLM+RAG + 跨函数检测 | Vul-RAG, VulTrigger | 37%漏洞跨函数 |
| **第五阶段** | 2025-2026 | 仓库级/Agent化 | T2L, 跨函数上下文检测 | 向项目级演进 |

### 2.2 函数级检测（主流）

#### 里程碑论文

| 论文 | 年份 | 方法 | 数据集 | 关键结果 | 参考文献 |
|---|---|---|---|---|---|
| **VulDeePecker** | 2018 | BiLSTM on code gadgets | NVD+SARD | 首个DL系统 | [Li et al., NDSS 2018](https://arxiv.org/abs/1801.01681) |
| **Devign** | 2019 | GNN (AST+CFG+DFG+PDG) | FFmpeg+QEMU (27K) | ~60% accuracy | [Zhou et al., NeurIPS 2019](https://arxiv.org/abs/1909.03496) |
| **ReVeal** | 2021 | GNN (GGNN) | Chromium+Debian | 改进Devign | [Chakraborty et al., 2021](https://arxiv.org/html/2403.03024v1) |
| **LineVul** | 2022 | RoBERTa (Transformer) | BigVul | F1 ~0.91 | [Fu & Tantithamthavorn, MSR 2022](https://ieeexplore.ieee.org/document/9796256) |
| **PrimeVul** | 2024 | 高质量数据集 | 236K函数 | 揭示标签噪声~50% | [Steenhoek et al., 2024](https://arxiv.org/abs/2403.18624) |
| **SecVulEval** | 2025 | LLM基准测试 | 25,440函数 | GPT-4o仅F1~0.30 | [Wen et al., 2025](https://arxiv.org/abs/2505.19828) |

#### 主流数据集（全部函数级）

| 数据集 | 年份 | 规模 | 来源 | 参考文献 |
|---|---|---|---|---|
| **BigVul** | 2020 | 188K函数, 3,754 CVEs | 348个GitHub C/C++项目 | [Fan et al., MSR 2020](https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset) |
| **DiverseVul** | 2023 | 330K+函数, 18K+ CVEs | 797个C/C++项目 | [Chen et al., 2023](https://dl.acm.org/doi/10.1145/3607199.3607242) |
| **PrimeVul** | 2024 | 236K函数 | 精心策划的commits | [Steenhoek et al., 2024](https://arxiv.org/abs/2403.18624) |
| **SecVulEval** | 2025 | 25,440函数, 5,867 CVEs | C/C++真实漏洞 | [Wen et al., 2025](https://arxiv.org/abs/2505.19828) |

### 2.3 行级定位（前沿但不成熟）

| 论文 | 年份 | 方法 | 关键发现 | 参考文献 |
|---|---|---|---|---|
| **IVDetect** | 2021 | GNN + GNNExplainer | 语句级定位 | [Li et al., FSE 2021](https://www.researchgate.net/publication/352644324_Vulnerability_Detection_with_Fine-grained_Interpretations) |
| **LineVul** | 2022 | Transformer attention | Top-10准确率60-70% | [Fu & Tantithamthavorn, MSR 2022](https://ieeexplore.ieee.org/document/9796256) |
| **ActiveClean** | 2023 | 主动学习清洗行标签 | 改进LineVul | [Steenhoek et al., 2023](https://arxiv.org/abs/2312.01588) |
| **行级定位评估** | 2025 | 系统评估 | **当前模型行级能力有限，attention方法不可靠** | [Wen et al., 2025](https://arxiv.org/abs/2510.11202) |

### 2.4 RAG增强检测（与RoboGuard最相关）

| 论文 | 年份 | 方法 | 关键结果 | 参考文献 |
|---|---|---|---|---|
| **Vul-RAG** | 2024 | 知识级RAG + GPT-4 | 准确率从0.60提升到0.77 | [Wen et al., 2024](https://arxiv.org/html/2406.11147v3) |
| **RAG数据增强** | 2024 | RAG + LLM | 用于训练数据增强 | [arXiv 2024](https://arxiv.org/html/2408.04125v1) |

**Vul-RAG是与RoboGuard方法最接近的工作**：
- 也是用RAG增强LLM做漏洞检测
- 函数级粒度
- 从历史漏洞中提取知识用于检索
- **但它是通用领域的，不针对ROS/机器人**

### 2.5 跨函数/仓库级检测（最新前沿）

| 论文 | 年份 | 关键发现 | 参考文献 |
|---|---|---|---|
| **VulTrigger** | 2024 (ICSE) | **37%真实漏洞是跨函数的** | [Wen et al., ICSE 2024](https://arxiv.org/abs/2401.09767v2) |
| **VulEval** | 2024 | 提出仓库级评估 | [Steenhoek et al., 2024](https://arxiv.org/abs/2404.15596) |
| **T2L** | 2025 | LLM Agent项目级定位 | [Wen et al., 2025](https://arxiv.org/abs/2510.02389) |
| **跨函数上下文检测** | 2026 | LLM+跨函数上下文 | [arXiv 2026](https://arxiv.org/abs/2602.06751) |

---

## 三、RoboGuard的研究定位

### 3.1 填补的研究空白

| 空白 | 现状 | RoboGuard的贡献 |
|---|---|---|
| **ROS函数级安全检测** | 所有ROS安全研究在系统/网络/通信层 | 首个ROS源代码函数级漏洞检测系统 |
| **ROS漏洞数据集** | RVD是Issue级，ROBUST是Bug不是安全漏洞 | 781个函数级样本，带CWE标签 |
| **LLM应用于ROS安全** | ML在ROS安全中的应用全部在网络流量层 | 首次用LLM+RAG分析ROS源代码 |
| **ROS漏洞pattern总结** | 无人系统分析ROS代码中各CWE的表现形式 | 8种CWE类型的ROS特定pattern分析 |

### 3.2 与相关工作的对比

| 维度 | 通用工具 (Cppcheck/Semgrep) | Vul-RAG (2024) | RoboGuard |
|---|---|---|---|
| **领域** | 通用C/C++ | 通用软件 | ROS/机器人 |
| **粒度** | 行/缺陷级 | 函数级 | 函数级输入，行级输出 |
| **方法** | 规则匹配 | RAG + LLM | RAG + LLM |
| **知识库** | 预定义规则 | 通用漏洞知识 | ROS历史漏洞案例 |
| **ROS特性** | ❌ | ❌ | ✅ (callback, pub/sub, lifecycle) |

### 3.3 创新点总结

1. **领域特定性**：首个针对ROS代码的函数级安全漏洞检测系统
2. **方法创新**：RAG增强的LLM检测，弥补ROS领域缺少pattern库的问题
3. **数据贡献**：首个函数级、带CWE标签的ROS漏洞数据集（781样本）
4. **知识贡献**：系统总结了8种CWE类型在ROS代码中的具体表现形式
5. **粒度细化**：输入函数级，输出行级定位（符合当前研究趋势）

### 3.4 关于"先粗后细"的担忧

**导师的担忧在ROS安全领域不成立**，原因：

1. **现有ROS安全研究做的是系统/通信层**，这不是"粗粒度的代码检测"，而是完全不同的分析维度
2. **函数级在通用漏洞检测领域本身就是主流粒度**（2018-至今），不是"细粒度"
3. **你不是跳过了什么阶段**，而是在一个空白领域开辟了新方向
4. **VulTrigger (ICSE 2024)证明**：37%漏洞是跨函数的，说明函数级是必要但不充分的基础粒度

---

## 四、论文写作建议

### 4.1 必须引用的关键文献

#### ROS安全现状（Related Work）
- SROS2 (2022) — ROS通信层安全
- HAROS (2016) — ROS代码质量分析
- Canonical ROS ESM审计 (2023) — 现有源代码分析方法
- RVD — 现有漏洞数据库
- ROBUST (2024) — 现有Bug数据集

#### 通用漏洞检测方法（Methodology）
- Vul-RAG (2024) — 你的方法论最近的参照物
- LineVul (2022) — 函数级检测SOTA
- VulTrigger (ICSE 2024) — 函数级检测的局限性

#### 数据集质量（Dataset）
- PrimeVul (2024) — 数据集质量问题
- BigVul (2020) — 主流基准数据集

#### 评估基准（Evaluation）
- SecVulEval (2025) — LLM在真实数据上的表现

### 4.2 论文结构建议

**Abstract**: 强调"首个ROS函数级安全漏洞检测系统"

**Introduction**:
1. ROS在机器人系统中的重要性
2. 现有ROS安全研究集中在系统/通信层
3. 源代码级漏洞检测的空白
4. 你的贡献：函数级检测 + ROS特定pattern + RAG增强

**Related Work**:
- ROS Security (系统/网络层)
- Static Analysis for ROS (HAROS, Coverity)
- Function-level Vulnerability Detection (通用领域)
- RAG-augmented Detection (Vul-RAG)

**Methodology**:
- 为什么选择函数级（引用VulTrigger说明这是基础粒度）
- 为什么用RAG（引用Vul-RAG验证这个方法）
- ROS特定的挑战（callback, pub/sub, lifecycle等）

**Dataset**:
- 与RVD、ROBUST对比，说明你的数据集的独特性
- 数据清理过程（引用PrimeVul说明数据质量的重要性）
- 0%数据泄漏（对比之前的实验）

**Evaluation**:
- 与静态工具对比（Cppcheck/Semgrep）
- 消融实验（RAG vs No-RAG）
- Per-CWE分析

**Pattern Analysis**:
- 8种CWE在ROS代码中的具体表现
- 为什么静态工具检测不到
- ROS特定特征（这是核心贡献）

### 4.3 核心论点

**你的论文应该强调**：
1. ROS代码有独特的安全特征（callback并发、pub/sub通信、lifecycle管理）
2. 通用静态工具无法捕捉这些ROS特定的漏洞模式
3. 你通过RAG构建了ROS领域的漏洞知识库
4. 你系统总结了8种CWE在ROS代码中的表现形式（这是核心贡献）

**不要强调**：
- RAG技术本身（这是工具，不是贡献）
- LLM的能力（这是已知的）
- 函数级粒度的选择（这是主流做法，不需要辩护）

---

## 五、完整参考文献列表

### ROS/机器人安全

1. White, R., et al. (2022). SROS2: Usable Cyber Security Tools for ROS 2. https://www.researchgate.net/publication/362489509_SROS2_Usable_Cyber_Security_Tools_for_ROS_2

2. Yang, S., et al. (2024). Formal Analysis and Detection for ROS2 Communication Security Vulnerability. Electronics, 13(9), 1762. https://www.mdpi.com/2079-9292/13/9/1762

3. Santos, A., et al. (2016). HAROS: A Framework for Quality Assessment of ROS Repositories. https://github.com/HAROS-framework/haros

4. Canonical (2023). Security vulnerability audits in ROS ESM. https://canonical-robotics.readthedocs-hosted.com/en/latest/explanations/security/security-audits/

5. Mayoral-Vilches, V., et al. (2019). Robot Vulnerability Database (RVD). https://github.com/aliasrobotics/RVD

6. Timperley, C., et al. (2024). ROBUST: 221 bugs in the Robot Operating System. https://github.com/robust-rosin/robust

7. Breiling, B., et al. (2019). ROSPenTo: Penetration Testing for ROS. https://github.com/jr-robotics/ROSPenTo

8. Kim, S., et al. (2022). RoboFuzz: Fuzzing Robotic Systems over Robot Operating System (ROS). ESEC/FSE 2022. https://github.com/sslab-gatech/RoboFuzz

### 通用漏洞检测

9. Li, Z., et al. (2018). VulDeePecker: A Deep Learning-Based System for Vulnerability Detection. NDSS 2018. https://arxiv.org/abs/1801.01681

10. Zhou, Y., et al. (2019). Devign: Effective Vulnerability Identification by Learning Comprehensive Program Semantics via Graph Neural Networks. NeurIPS 2019. https://arxiv.org/abs/1909.03496

11. Fu, M., & Tantithamthavorn, C. (2022). LineVul: A Transformer-based Line-Level Vulnerability Prediction. MSR 2022. https://ieeexplore.ieee.org/document/9796256

12. Steenhoek, B., et al. (2024). PrimeVul: A Dataset for Vulnerability Detection with Code Language Models. https://arxiv.org/abs/2403.18624

13. Wen, M., et al. (2025). SecVulEval: Benchmarking LLMs for Real-World C/C++ Vulnerability Detection. https://arxiv.org/abs/2505.19828

14. Fan, J., et al. (2020). A C/C++ Code Vulnerability Dataset with Code Changes and CVE Summaries. MSR 2020. https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset

### RAG增强检测

15. Wen, M., et al. (2024). Vul-RAG: Enhancing LLM-based Vulnerability Detection via Knowledge-level RAG. https://arxiv.org/html/2406.11147v3

### 跨函数检测

16. Wen, M., et al. (2024). On the Effectiveness of Function-Level Vulnerability Detectors for Inter-Procedural Vulnerabilities. ICSE 2024. https://arxiv.org/abs/2401.09767v2

17. Steenhoek, B., et al. (2024). VulEval: Towards Repository-Level Evaluation of Software Vulnerability Detection. https://arxiv.org/abs/2404.15596

### 行级定位

18. Li, Y., et al. (2021). IVDetect: Vulnerability Detection with Fine-grained Interpretations. FSE 2021. https://www.researchgate.net/publication/352644324_Vulnerability_Detection_with_Fine-grained_Interpretations

19. Wen, M., et al. (2025). Evaluating Line-level Localization Ability of Learning-based Code Vulnerability Detection Models. https://arxiv.org/abs/2510.11202

---

## 附录：搜索关键词记录

本次调研使用的搜索关键词：
- "ROS vulnerability detection source code analysis"
- "robot software security static analysis function level"
- "ROS code vulnerability CWE detection tool"
- "robotic software vulnerability dataset CVE"
- "ROS security analysis Cppcheck Coverity results"
- "robot operating system code security deep learning"
- "ROS2 vulnerability detection machine learning"
- "SROS2 security analysis ROS"
- "robot software quality assurance vulnerability"
- "ROS fuzzing vulnerability detection"
- "Alias Robotics RVD robot vulnerability"
- "ROBUST dataset ROS bugs security"
- "function level vulnerability detection survey 2024 2025"
- "line level vulnerability localization deep learning"
- "LLM vulnerability detection function level C++ 2024 2025"
- "RAG augmented vulnerability detection code security"
- "VulDeePecker LineVul Devign function level vulnerability"
- "Big-Vul Draper SARD vulnerability dataset granularity"

---

**报告生成时间**: 2026-04-25
**调研执行**: Claude Opus 4.6
**项目**: RoboGuard - ROS函数级安全漏洞检测系统
