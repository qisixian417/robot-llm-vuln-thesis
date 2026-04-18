"""Generate dataset_sample.jsonl with clean, realistic ROS vulnerability samples."""
import json
from pathlib import Path

samples = [
    {
        "id": "ros_comm_CVE-2023-12345_001",
        "repo": "ros/ros_comm",
        "cwe_id": "CWE-119",
        "cwe_name": "Buffer Overflow",
        "language": "C++",
        "vulnerable_code": (
            "void TransportTCP::read(uint8_t* buffer, uint32_t size) {\n"
            "  memcpy(buffer, recv_buffer_, size);\n"
            "  recv_offset_ += size;\n"
            "}"
        ),
        "label": 1,
        "severity": "HIGH",
        "description": "TCP传输层memcpy未检查size是否超过buffer容量",
    },
    {
        "id": "ros2_rclcpp_race_004",
        "repo": "ros2/rclcpp",
        "cwe_id": "CWE-362",
        "cwe_name": "Race Condition",
        "language": "C++",
        "vulnerable_code": (
            'class SensorNode : public rclcpp::Node {\n'
            'public:\n'
            '  SensorNode() : Node("sensor") {\n'
            '    sub_ = create_subscription<sensor_msgs::msg::Image>(\n'
            '      "/camera", 10, [this](auto msg) { onImage(msg); });\n'
            '    timer_ = create_wall_timer(std::chrono::milliseconds(100),\n'
            '      [this]() { processLatest(); });\n'
            '  }\n'
            'private:\n'
            '  void onImage(sensor_msgs::msg::Image::SharedPtr msg) {\n'
            '    latest_image_ = msg;\n'
            '  }\n'
            '  void processLatest() {\n'
            '    if (latest_image_) analyze(latest_image_->data);\n'
            '  }\n'
            '  sensor_msgs::msg::Image::SharedPtr latest_image_;\n'
            '};'
        ),
        "label": 1,
        "severity": "HIGH",
        "description": "ROS2 MultiThreadedExecutor下订阅和定时器回调并发访问latest_image_无锁保护",
    },
    {
        "id": "moveit2_benign_003",
        "repo": "ros-planning/moveit2",
        "cwe_id": None,
        "cwe_name": None,
        "language": "C++",
        "vulnerable_code": (
            "bool PlanningScene::isStateValid(const RobotState& state) {\n"
            "  return state.satisfiesBounds() && !state.hasCollisions(getPlanningSceneMonitor());\n"
            "}"
        ),
        "label": 0,
        "severity": "NONE",
        "description": "正常的规划场景有效性检查",
    },
    {
        "id": "gazebo_ros_uaf_005",
        "repo": "ros-simulation/gazebo_ros_pkgs",
        "cwe_id": "CWE-416",
        "cwe_name": "Use After Free",
        "language": "C++",
        "vulnerable_code": (
            "void GazeboRosApiPlugin::onUpdate() {\n"
            "  delete model_ptr_;\n"
            "  model_ptr_->Detach();\n"
            "  world_->RemoveModel(model_name_);\n"
            "}"
        ),
        "label": 1,
        "severity": "CRITICAL",
        "description": "释放model_ptr_后继续调用其方法，导致use-after-free",
    },
    {
        "id": "sensor_msgs_overflow_006",
        "repo": "ros2/common_interfaces",
        "cwe_id": "CWE-190",
        "cwe_name": "Integer Overflow",
        "language": "C++",
        "vulnerable_code": (
            "size_t PointCloud2Iterator::calculateOffset(int x, int y) {\n"
            "  return x * y * point_step_;\n"
            "}"
        ),
        "label": 1,
        "severity": "MEDIUM",
        "description": "点云偏移量整数乘法可能溢出",
    },
    {
        "id": "tf2_memleak_007",
        "repo": "ros2/geometry2",
        "cwe_id": "CWE-401",
        "cwe_name": "Memory Leak",
        "language": "C++",
        "vulnerable_code": (
            "void BufferCore::setTransform(const TransformStamped& transform) {\n"
            "  TransformStorage* storage = new TransformStorage(transform);\n"
            "  cache_[transform.header.frame_id] = storage;\n"
            "}"
        ),
        "label": 1,
        "severity": "MEDIUM",
        "description": "每次setTransform分配新内存但不释放旧内存，导致内存泄漏",
    },
    {
        "id": "control_toolbox_div_008",
        "repo": "ros-controls/control_toolbox",
        "cwe_id": "CWE-369",
        "cwe_name": "Divide By Zero",
        "language": "C++",
        "vulnerable_code": (
            "double Pid::computeCommand(double error, double dt) {\n"
            "  double derivative = (error - prev_error_) / dt;\n"
            "  prev_error_ = error;\n"
            "  return kp_ * error + kd_ * derivative;\n"
            "}"
        ),
        "label": 1,
        "severity": "LOW",
        "description": "PID控制器在dt为零时产生除零错误",
    },
    {
        "id": "image_transport_benign_009",
        "repo": "ros-perception/image_transport",
        "cwe_id": None,
        "cwe_name": None,
        "language": "C++",
        "vulnerable_code": (
            "void Subscriber::subscribe(const std::string& topic) {\n"
            '  if (topic.empty()) throw std::invalid_argument("Topic name cannot be empty");\n'
            "  impl_ = std::make_shared<Impl>(node_, topic, qos_);\n"
            "}"
        ),
        "label": 0,
        "severity": "NONE",
        "description": "安全的话题订阅，包含输入验证和智能指针",
    },
    {
        "id": "actionlib_benign_010",
        "repo": "ros/actionlib",
        "cwe_id": None,
        "cwe_name": None,
        "language": "C++",
        "vulnerable_code": (
            "void ServerGoalHandle::setSucceeded(const Result& result) {\n"
            "  boost::recursive_mutex::scoped_lock lock(action_server_->lock_);\n"
            "  status_tracker_.status_.status = GoalStatus::SUCCEEDED;\n"
            "  action_server_->publishResult(status_tracker_.status_, result);\n"
            "}"
        ),
        "label": 0,
        "severity": "NONE",
        "description": "安全的Action目标状态设置，使用互斥锁保护共享状态",
    },
    {
        "id": "ros_comm_cmdinj_011",
        "repo": "ros/ros_comm",
        "cwe_id": "CWE-78",
        "cwe_name": "OS Command Injection",
        "language": "Python",
        "vulnerable_code": (
            "def reindex(self, filename):\n"
            "    cmd = 'rosbag reindex ' + filename\n"
            "    os.system(cmd)"
        ),
        "label": 1,
        "severity": "CRITICAL",
        "description": "用户输入文件名直接拼接到shell命令中，命令注入风险",
    },
    {
        "id": "diagnostic_updater_benign_012",
        "repo": "ros/diagnostics",
        "cwe_id": None,
        "cwe_name": None,
        "language": "C++",
        "vulnerable_code": (
            "void DiagnosticUpdater::update() {\n"
            "  std::vector<diagnostic_msgs::DiagnosticStatus> statuses;\n"
            "  for (auto& task : tasks_) {\n"
            "    diagnostic_updater::DiagnosticStatusWrapper wrapper;\n"
            "    task->run(wrapper);\n"
            "    statuses.push_back(wrapper);\n"
            "  }\n"
            "  publisher_.publish(statuses);\n"
            "}"
        ),
        "label": 0,
        "severity": "NONE",
        "description": "安全的诊断信息更新，顺序执行任务并发布",
    },
    {
        "id": "rclcpp_shared_state_race_013",
        "repo": "ros2/rclcpp",
        "cwe_id": "CWE-362",
        "cwe_name": "Race Condition",
        "language": "C++",
        "vulnerable_code": (
            'class NavigationNode : public rclcpp::Node {\n'
            'public:\n'
            '  NavigationNode() : Node("nav"), goal_active_(false) {\n'
            '    goal_sub_ = create_subscription<geometry_msgs::msg::PoseStamped>(\n'
            '      "/goal", 10, [this](auto msg) { onGoal(msg); });\n'
            '    status_sub_ = create_subscription<std_msgs::msg::Bool>(\n'
            '      "/reached", 10, [this](auto msg) { onReached(msg); });\n'
            '  }\n'
            'private:\n'
            '  void onGoal(geometry_msgs::msg::PoseStamped::SharedPtr msg) {\n'
            '    goal_active_ = true;\n'
            '    current_goal_ = *msg;\n'
            '  }\n'
            '  void onReached(std_msgs::msg::Bool::SharedPtr msg) {\n'
            '    if (msg->data && goal_active_) goal_active_ = false;\n'
            '  }\n'
            '  bool goal_active_;\n'
            '  geometry_msgs::msg::PoseStamped current_goal_;\n'
            '};'
        ),
        "label": 1,
        "severity": "HIGH",
        "description": "ROS2多线程执行器下两个订阅回调并发访问goal_active_无互斥锁",
    },
    {
        "id": "nav2_path_sqli_014",
        "repo": "ros-planning/navigation2",
        "cwe_id": "CWE-89",
        "cwe_name": "SQL Injection",
        "language": "C++",
        "vulnerable_code": (
            "bool MapIO::loadMapFromDB(const std::string& map_name) {\n"
            "  std::string query = \"SELECT * FROM maps WHERE name = '\" + map_name + \"'\";\n"
            "  return db_->execute(query);\n"
            "}"
        ),
        "label": 1,
        "severity": "HIGH",
        "description": "地图名称未参数化直接拼接到SQL查询，SQL注入风险",
    },
    {
        "id": "moveit_bounds_015",
        "repo": "ros-planning/moveit",
        "cwe_id": "CWE-125",
        "cwe_name": "Out-of-bounds Read",
        "language": "C++",
        "vulnerable_code": (
            "double RobotState::getJointPosition(size_t index) {\n"
            "  return position_[index];\n"
            "}"
        ),
        "label": 1,
        "severity": "MEDIUM",
        "description": "关节位置访问无边界检查，可能导致越界读取",
    },
    {
        "id": "rqt_benign_016",
        "repo": "ros-visualization/rqt",
        "cwe_id": None,
        "cwe_name": None,
        "language": "Python",
        "vulnerable_code": (
            "def main(argv=None):\n"
            "    parser = argparse.ArgumentParser()\n"
            "    parser.add_argument('--perspective-file', type=str)\n"
            "    args = parser.parse_args(argv)\n"
            "    if args.perspective_file:\n"
            "        if not os.path.isfile(args.perspective_file):\n"
            "            raise SystemExit('Perspective file not found')\n"
            "    return rqt_gui.main.Main().main(argv)"
        ),
        "label": 0,
        "severity": "NONE",
        "description": "安全的参数解析，使用argparse并验证文件路径",
    },
    {
        "id": "pcl_ros_format_017",
        "repo": "ros-perception/perception_pcl",
        "cwe_id": "CWE-134",
        "cwe_name": "Format String",
        "language": "C++",
        "vulnerable_code": (
            "void PCLNodelet::logError(const std::string& msg) {\n"
            "  NODELET_ERROR(msg.c_str());\n"
            "}"
        ),
        "label": 1,
        "severity": "HIGH",
        "description": "用户控制字符串直接作为printf格式参数，格式字符串漏洞",
    },
    {
        "id": "rosbridge_benign_018",
        "repo": "RobotWebTools/rosbridge_suite",
        "cwe_id": None,
        "cwe_name": None,
        "language": "Python",
        "vulnerable_code": (
            "def incoming(self, message_string):\n"
            "    try:\n"
            "        msg = json.loads(message_string)\n"
            "    except json.JSONDecodeError:\n"
            "        self.log('error', 'Invalid JSON')\n"
            "        return\n"
            "    if not isinstance(msg, dict):\n"
            "        self.log('error', 'Message must be a dict')\n"
            "        return\n"
            "    op = msg.get('op')\n"
            "    if op not in self.OPERATIONS:\n"
            "        self.log('error', 'Unknown operation')\n"
            "        return\n"
            "    self.OPERATIONS[op](msg)"
        ),
        "label": 0,
        "severity": "NONE",
        "description": "安全的JSON消息处理，白名单验证操作类型",
    },
    {
        "id": "robot_localization_toctou_019",
        "repo": "cra-ros-pkg/robot_localization",
        "cwe_id": "CWE-367",
        "cwe_name": "TOCTOU Race Condition",
        "language": "C++",
        "vulnerable_code": (
            "bool Ekf::loadConfig(const std::string& file) {\n"
            "  if (access(file.c_str(), R_OK) == 0) {\n"
            "    std::ifstream config(file);\n"
            "    return parseConfig(config);\n"
            "  }\n"
            "  return false;\n"
            "}"
        ),
        "label": 1,
        "severity": "LOW",
        "description": "先用access()检查文件权限再打开，存在TOCTOU竞态条件",
    },
    {
        "id": "rviz_benign_020",
        "repo": "ros-visualization/rviz",
        "cwe_id": None,
        "cwe_name": None,
        "language": "C++",
        "vulnerable_code": (
            "void RobotModelDisplay::load() {\n"
            "  std::string description;\n"
            "  if (!node_->getParam(robot_description_property_->getStdString(), description)) {\n"
            '    setStatus(StatusProperty::Error, "URDF", "No URDF model");\n'
            "    return;\n"
            "  }\n"
            "  robot_model_ = std::make_shared<urdf::Model>();\n"
            "  if (!robot_model_->initString(description)) {\n"
            '    setStatus(StatusProperty::Error, "URDF", "Failed to parse URDF");\n'
            "    return;\n"
            "  }\n"
            "}"
        ),
        "label": 0,
        "severity": "NONE",
        "description": "安全的机器人模型加载，包含错误处理和智能指针管理",
    },
]

out = Path("data/demos/dataset_sample.jsonl")
with open(out, "w", encoding="utf-8") as f:
    for s in samples:
        f.write(json.dumps(s, ensure_ascii=False) + "\n")

label0 = sum(1 for s in samples if s["label"] == 0)
label1 = sum(1 for s in samples if s["label"] == 1)
print(f"Written {len(samples)} samples to {out}")
print(f"  label=0 (benign): {label0}")
print(f"  label=1 (vuln):   {label1}")
