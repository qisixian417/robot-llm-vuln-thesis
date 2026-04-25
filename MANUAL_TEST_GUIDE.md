# RoboGuard UI 手动测试指南

**日期**: 2024-04-24
**目的**: 模拟用户使用Web界面进行漏洞检测

---

## 📋 测试前准备

### 1. 确认环境配置

确保 `.env` 文件已配置：
```bash
DASHSCOPE_API_KEY=your_api_key_here
MODEL_NAME=qwen-plus
```

### 2. 确认向量数据库已构建

```bash
# 如果还没有构建，运行：
python3 scripts/build_chroma_db.py --reset --corpus data/rag_corpus_cleaned.jsonl
```

---

## 🚀 启动步骤

### 步骤1：打开终端

在项目根目录下打开终端：
```bash
cd /Users/yuan/Desktop/robot-llm-vuln-thesis
```

### 步骤2：启动Web界面

```bash
./start_ui.sh
```

或者：
```bash
streamlit run app.py
```

### 步骤3：打开浏览器

启动后会自动打开浏览器，或手动访问：
```
http://localhost:8501
```

---

## 🧪 测试样本

我为你准备了5个测试样本，涵盖不同的CWE类型和场景。

---

### 测试样本 1：CWE-362 (Race Condition) - 竞态条件

**预期结果**: ✅ 有漏洞

**代码**（复制下面的代码到UI中）：
```cpp
  const Eigen::VectorXd kTotalWrench = kAmassVec + kDvec + kCmatVec;
```

**说明**：
- 这是一个竞态条件漏洞
- 系统应该检测到 CWE-362
- 置信度应该较高

---

### 测试样本 2：CWE-401 (Memory Leak) - 内存泄漏

**预期结果**: ✅ 有漏洞

**代码**（复制下面的代码到UI中）：
```cpp
#include <set>

#include <ignition/common/Profiler.hh>
#include <ignition/gui/Application.hh>
#include <ignition/gui/GuiEvents.hh>
#include <ignition/gui/MainWindow.hh>
#include <ignition/plugin/Register.hh>
#include <ignition/rendering/RenderingIface.hh>
#include <ignition/rendering/Scene.hh>

#include "ignition/gazebo/EntityComponentManager.hh"
#include "ignition/gazebo/components/Name.hh"
#include "ignition/gazebo/components/World.hh"
#include "ignition/gazebo/gui/GuiEvents.hh"
#include "ignition/gazebo/rendering/RenderUtil.hh"

namespace ignition
{
namespace gazebo
{
inline namespace IGNITION_GAZEBO_VERSION_NAMESPACE {
  /// \brief Private data class for GzSceneManager
  class GzSceneManagerPrivate
  {
    /// \brief Update the 3D scene based on the latest state of the ECM.
    public: void OnRender();

    //// \brief Pointer to the rendering scene
    public: rendering::ScenePtr scene;

    /// \brief Rendering utility
    public: RenderUtil renderUtil;
  };
}
}
}
```

**说明**：
- 这是一个内存泄漏漏洞
- 系统应该检测到 CWE-401
- 可能涉及资源管理问题

---

### 测试样本 3：CWE-476 (Null Pointer) - 空指针解引用

**预期结果**: ✅ 有漏洞

**代码**（复制下面的代码到UI中）：
```cpp
get_global_logging_mutex()
{
  static auto mutex = std::make_shared<std::recursive_mutex>();
  if (RCUTILS_UNLIKELY(!mutex)) {
    throw std::runtime_error("rclcpp global logging mutex is a nullptr");
  }
  return mutex;
}
```

**说明**：
- 这是一个空指针解引用漏洞
- 系统应该检测到 CWE-476
- 涉及空指针检查

---

### 测试样本 4：无漏洞代码（安全代码）

**预期结果**: ❌ 无漏洞

**代码**（复制下面的代码到UI中）：
```cpp
                const std::shared_ptr<const sdf::Element> &_sdf,
                EntityComponentManager &_ecm,
                EventManager &_eventMgr) override;

  // Documentation inherited
  public: void PreUpdate(const UpdateInfo &_info,
                EntityComponentManager &_ecm) override;

  // Documentation inherited
  public: void Update(const UpdateInfo &_info,
                EntityComponentManager &_ecm) override;

  // Documentation inherited
  public: void PostUpdate(const UpdateInfo &_info,
                const EntityComponentManager &_ecm) override;

  // Documentation inherited
  public: void Reset(const UpdateInfo &_info,
                            EntityComponentManager &_ecm) override;

  /// \brief Function to call every time  we configure a world
  public: std::function<void(const Entity &_entity,
                const std::shared_ptr<const sdf::Element> &_sdf,
                EntityComponentManager &_ecm,
                EventManager &_eventMgr)>
      configureCallback;

  /// \brief Function to call every pre-update
  public: std::function<void(const UpdateInfo &, EntityComponentManager &)>
      preUpdateCallback;

  /// \brief Function to call every update
  public: std::function<void(const UpdateInfo &, EntityComponentManager &)>
      updateCallback;

  /// \brief Function to call every post-update
  public: std::function<void(const UpdateInfo &,
      const EntityComponentManager &)> postUpdateCallback;

  /// \brief Reset callback
  public: std::function<void(const UpdateInfo &,
      EntityComponentManager &)> resetCallback;
};

/////////////////////////////////////////////////
void HelperSystem::Configure(
                const Entity &_entity,
                const std::shared_ptr<const sdf::Element> &_sdf,
                EntityComponentManager &_ecm,
                EventManager &_eventMgr)
{
```

**说明**：
- 这是安全的代码
- 系统应该判断为"无漏洞"
- 使用了安全的智能指针（std::shared_ptr）

---

### 测试样本 5：CWE-416 (Use After Free) - 释放后使用

**预期结果**: ✅ 有漏洞

**代码**（复制下面的代码到UI中）：
```cpp
  // Since the rmw event listener holds a reference to
  // this callback, we need to clear it on destruction of this class.
  // This clearing is not needed for other rclcpp entities like pub/subs, since
  // they do own the underlying rmw entities, which are destroyed
  // on their rclcpp destructors, thus no risk of dangling pointers.
  clear_on_ready_callback();
```

**说明**：
- 这是一个释放后使用（Use After Free）漏洞
- 系统应该检测到 CWE-416
- 涉及悬空指针问题

---

## 📝 详细测试步骤

### 步骤1：启动系统

1. 打开终端
2. 运行 `./start_ui.sh`
3. 等待浏览器自动打开（或手动访问 http://localhost:8501）

### 步骤2：测试第一个样本

1. **复制测试样本1的代码**（见上面）
2. **粘贴到Web界面的代码输入框**
3. **点击"🔍 开始检测"按钮**
4. **等待检测结果**（大约5-10秒）
5. **查看结果**：
   - 是否检测到漏洞？
   - 漏洞类型是什么？（应该是 CWE-362）
   - 置信度是多少？
   - 原因说明是否合理？
   - RAG检索到了几条参考知识？

### 步骤3：记录结果

在下面的表格中记录测试结果：

| 样本 | 预期结果 | 实际结果 | CWE类型 | 置信度 | RAG检索数 | 是否正确 |
|------|---------|---------|---------|--------|-----------|---------|
| 1    | 有漏洞   |         |         |        |           |         |
| 2    | 有漏洞   |         |         |        |           |         |
| 3    | 有漏洞   |         |         |        |           |         |
| 4    | 无漏洞   |         |         |        |           |         |
| 5    | 有漏洞   |         |         |        |           |         |

### 步骤4：重复测试其他样本

对每个测试样本重复步骤2和步骤3。

### 步骤5：测试预设示例（可选）

Web界面应该有4个预设示例代码，你也可以测试这些：
1. 缓冲区溢出示例
2. 命令注入示例
3. 内存泄漏示例
4. 安全代码示例

---

## 🎯 测试要点

### 检查项1：系统输出格式

系统应该输出以下5个字段：
- ✅ **是否存在漏洞** (has_vulnerability: true/false)
- ✅ **漏洞类型** (vulnerability_type: CWE-XXX)
- ✅ **漏洞原因** (reason: 详细说明)
- ✅ **置信度** (confidence: 0.0-1.0)
- ✅ **RAG检索结果** (retrieved_knowledge: 3条参考知识)

### 检查项2：RAG是否工作

- 每次检测应该显示"RAG检索到 X 条参考知识"
- 应该显示检索到的历史漏洞案例
- 检索结果应该与输入代码相关

### 检查项3：检测准确性

- 有漏洞的样本应该被检测出来
- 无漏洞的样本应该判断为安全
- CWE类型应该正确
- 置信度应该合理（有漏洞的应该>0.7，无漏洞的应该<0.5）

---

## 🐛 常见问题

### 问题1：启动失败

**错误**: `ModuleNotFoundError: No module named 'streamlit'`

**解决**:
```bash
pip install -r requirements.txt
```

### 问题2：API Key错误

**错误**: `Invalid API key`

**解决**:
1. 检查 `.env` 文件是否存在
2. 确认 `DASHSCOPE_API_KEY` 已正确填写
3. 重启Web界面

### 问题3：向量数据库为空

**错误**: `RAG知识库为空`

**解决**:
```bash
python3 scripts/build_chroma_db.py --reset --corpus data/rag_corpus_cleaned.jsonl
```

### 问题4：检测速度慢

**原因**: LLM API调用需要时间

**正常情况**: 每次检测需要5-15秒

---

## 📊 测试结果示例

### 正确的检测结果示例

**输入**: 测试样本1（CWE-362）

**输出**:
```
✅ 检测到漏洞

漏洞类型: CWE-362 (Race Condition)
置信度: 0.92

原因:
代码中存在竞态条件，多个线程可能同时访问共享变量
kTotalWrench，导致数据不一致。

RAG检索结果: 3条
1. ros/ros_comm - CWE-362: Fix race condition in topic subscription
2. ros2/rclcpp - CWE-362: Fix race condition in callback handling
3. gazebosim/gz-sim - CWE-362: Fix race condition in physics update
```

---

## 📸 截图建议

测试时建议截图保存以下内容：
1. 系统主界面
2. 输入代码的界面
3. 检测结果（有漏洞）
4. 检测结果（无漏洞）
5. RAG检索结果展示

这些截图可以用于：
- 论文插图
- 答辩PPT
- 演示视频

---

## ✅ 测试完成检查清单

- [ ] 成功启动Web界面
- [ ] 测试样本1（CWE-362）
- [ ] 测试样本2（CWE-401）
- [ ] 测试样本3（CWE-476）
- [ ] 测试样本4（无漏洞）
- [ ] 测试样本5（CWE-416）
- [ ] 测试预设示例（可选）
- [ ] 记录测试结果
- [ ] 截图保存
- [ ] 验证RAG工作正常
- [ ] 验证输出格式正确

---

## 🎓 用于答辩

### 演示建议

1. **选择1-2个代表性样本**（如CWE-362和无漏洞样本）
2. **现场演示检测过程**
3. **展示RAG检索结果**
4. **解释检测原理**

### 回答评委问题

**Q: 系统如何工作？**
A: 系统首先通过RAG从228个历史漏洞案例中检索3个最相似的案例，
然后LLM基于这些案例分析输入代码是否存在类似的漏洞。

**Q: RAG的作用是什么？**
A: RAG提供历史漏洞案例作为参考，帮助LLM识别相似的漏洞模式，
提升检测准确率。

**Q: 为什么有时会误报？**
A: 系统基于语义相似度检索，可能检索到表面相似但实际安全的代码。
这是当前精确率50%的主要原因。

---

**祝测试顺利！** 🎉

如有问题，请查看 `README.md` 或 `WEB_UI_GUIDE.md`
