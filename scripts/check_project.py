#!/usr/bin/env python3
"""工程静态自检：不编译也能抓出的结构性错误。

检查项：
1. project.yml / workflow YAML 可解析
2. Config/Info.plist 可解析且关键 key 齐备
3. project.yml 引用的目录都存在且非空
4. 所有 .swift / .m / .h 文件的括号配对（跳过字符串与注释）
5. TODO / placeholder 密度
6. 硬编码密钥（示例占位符白名单）
7. README 必备小节
"""
import os
import re
import plistlib
import sys

FAIL = []
WARN = []


def fail(msg):
    FAIL.append(msg)
    print(f"[FAIL] {msg}")


def warn(msg):
    WARN.append(msg)
    print(f"[WARN] {msg}")


def ok(msg):
    print(f"[ OK ] {msg}")


def load_yaml(path):
    try:
        import yaml  # type: ignore
    except ImportError:
        warn("PyYAML 未安装，跳过 YAML 深度解析（仅做文本存在性检查）")
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except Exception as exc:  # noqa: BLE001
        fail(f"{path} 解析失败: {exc}")
        return None


def strip_code(src):
    """去掉注释与字符串字面量，返回可用于括号计数的骨架。"""
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            depth = 1
            i += 2
            while i < n and depth:
                if src.startswith("/*", i):
                    depth += 1
                    i += 2
                elif src.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            continue
        if c == '"':
            i += 1
            while i < n:
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


PAIRS = {"(": ")", "[": "]", "{": "}"}


def check_balance(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        src = fh.read()
    skeleton = strip_code(src)
    stack = []
    for idx, ch in enumerate(skeleton):
        if ch in PAIRS:
            stack.append((ch, idx))
        elif ch in PAIRS.values():
            if not stack:
                fail(f"{path}: 多余的 '{ch}'")
                return False
            opener, _ = stack.pop()
            if PAIRS[opener] != ch:
                line = skeleton.count("\n", 0, idx) + 1
                fail(f"{path}:{line} 括号不匹配（{opener} 对 {ch}）")
                return False
    if stack:
        line = skeleton.count("\n", 0, stack[-1][1]) + 1
        fail(f"{path}:{line} 未闭合的 '{stack[-1][0]}'")
        return False
    return True


def main(root="."):
    root = os.path.abspath(root)
    print(f"工程根目录: {root}")

    project = os.path.join(root, "project.yml")
    if not os.path.isfile(project):
        fail("缺少 project.yml")
        return 1
    spec = load_yaml(project)
    if spec:
        ok("project.yml 可解析")
        targets = spec.get("targets", {}) or {}
        for name, cfg in targets.items():
            for src in cfg.get("sources", []) or []:
                path = src if isinstance(src, str) else src.get("path")
                full = os.path.join(root, path)
                if not os.path.isdir(full):
                    fail(f"target {name} 的 sources 目录不存在: {path}")
                    continue
                files = [f for f in os.listdir(full) if not f.startswith(".")]
                if not files:
                    fail(f"target {name} 的 sources 目录是空的: {path}")
        for dep in (targets.get("REKitApp", {}) or {}).get("dependencies", []) or []:
            if isinstance(dep, dict) and "target" in dep:
                if dep["target"] not in targets:
                    fail(f"REKitApp 依赖了不存在的 target: {dep['target']}")
        ok("project.yml 引用关系自检完成")

    workflow_dir = os.path.join(root, ".github", "workflows")
    if os.path.isdir(workflow_dir):
        for name in os.listdir(workflow_dir):
            if name.endswith((".yml", ".yaml")):
                load_yaml(os.path.join(workflow_dir, name))
        ok("workflow YAML 检查完成")
    else:
        fail("缺少 .github/workflows")

    info = os.path.join(root, "Config", "Info.plist")
    if not os.path.isfile(info):
        fail("缺少 Config/Info.plist")
    else:
        try:
            with open(info, "rb") as fh:
                pl = plistlib.load(fh)
            required = ["CFBundleIdentifier", "CFBundleExecutable", "CFBundleVersion",
                        "UILaunchScreen", "UISupportedInterfaceOrientations"]
            missing = [k for k in required if k not in pl]
            if missing:
                fail(f"Info.plist 缺少 key: {missing}")
            else:
                ok("Info.plist 关键 key 齐备")
        except Exception as exc:  # noqa: BLE001
            fail(f"Info.plist 解析失败: {exc}")

    swift_like = []
    for base, _dirs, files in os.walk(root):
        if any(seg in base for seg in (".git", "build", "artifacts")):
            continue
        for name in files:
            if name.endswith((".swift", ".m", ".h")):
                swift_like.append(os.path.join(base, name))
    if not swift_like:
        fail("没有任何源码文件")
    bad = 0
    for path in swift_like:
        if not check_balance(path):
            bad += 1
    if bad == 0:
        ok(f"{len(swift_like)} 个源码文件括号配对正常")

    placeholder = re.compile(r"\b(TODO|FIXME|placeholder|not implemented)\b", re.I)
    suspicious = []
    for path in swift_like:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        if placeholder.search(text):
            suspicious.append(os.path.relpath(path, root))
    if suspicious:
        warn(f"存在占位标记: {suspicious}")
    else:
        ok("无 TODO/FIXME 占位")

    secret = re.compile(r"(AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{10,}|ghp_[A-Za-z0-9]{30,})")
    allow = {"AKIAIOSFODNN7EXAMPLE"}
    leaked = []
    for base, _dirs, files in os.walk(root):
        if ".git" in base:
            continue
        for name in files:
            if not name.endswith((".swift", ".m", ".h", ".yml", ".plist", ".md", ".py", ".sh")):
                continue
            path = os.path.join(base, name)
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for match in secret.findall(fh.read()):
                    if match not in allow:
                        leaked.append((os.path.relpath(path, root), match[:8] + "..."))
    if leaked:
        fail(f"疑似硬编码密钥: {leaked}")
    else:
        ok("未发现硬编码密钥")

    readme = os.path.join(root, "README.md")
    if not os.path.isfile(readme):
        fail("缺少 README.md")
    else:
        with open(readme, "r", encoding="utf-8") as fh:
            text = fh.read()
        for section in ["架构", "使用", "构建", "能力", "边界"]:
            if section not in text:
                warn(f"README 缺少小节: {section}")
        ok("README 检查完成")

    print("\n结果: %d 个失败, %d 个警告" % (len(FAIL), len(WARN)))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
