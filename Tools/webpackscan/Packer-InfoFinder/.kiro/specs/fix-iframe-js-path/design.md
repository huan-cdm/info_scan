# Design Document: Fix Iframe JS Path Resolution

## Overview

修复 `ParseJs._download_js_by_source` 方法中对 iframe 发现的 JS 文件路径的错误处理。当前实现会对所有 JS 路径使用主页面的 `base_url` 进行 `urljoin`，导致已经是绝对 URL 的 iframe JS 路径被错误修改。

### 问题分析

**当前流程**:
1. `IframeParser._extract_js_from_html` 正确使用 iframe 的 URL 作为 `parent_url` 解析 JS 路径
2. 返回的 JS URL 已经是绝对路径（如 `http://180.97.197.34:9999/gps-web/js/chunk-common.20251112.js`）
3. `ParseJs._download_js_by_source` 对所有路径执行 `urljoin(self.base_url, path)`
4. 由于 `urljoin` 对绝对路径的处理方式，路径被错误修改

**根本原因**:
`_download_js_by_source` 中的路径处理逻辑没有区分已经是绝对 URL 的路径和相对路径。

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        ParseJs                               │
│  ┌─────────────────┐  ┌─────────────────┐                   │
│  │  IframeParser   │  │ InlinePattern   │                   │
│  │  (返回绝对URL)   │  │ Parser          │                   │
│  └────────┬────────┘  └────────┬────────┘                   │
│           │                    │                             │
│           ▼                    ▼                             │
│  ┌─────────────────────────────────────────┐                │
│  │     js_by_source (收集各来源的JS路径)     │                │
│  └────────────────────┬────────────────────┘                │
│                       │                                      │
│                       ▼                                      │
│  ┌─────────────────────────────────────────┐                │
│  │  _download_js_by_source                  │                │
│  │  ┌─────────────────────────────────┐    │                │
│  │  │ resolve_js_url() [新增]          │    │                │
│  │  │ - 检查是否绝对URL → 直接返回      │    │                │
│  │  │ - 检查是否协议相对 → 补充协议     │    │                │
│  │  │ - 相对路径 → urljoin             │    │                │
│  │  └─────────────────────────────────┘    │                │
│  └────────────────────┬────────────────────┘                │
│                       │                                      │
│                       ▼                                      │
│  ┌─────────────────────────────────────────┐                │
│  │           DownloadJs                     │                │
│  └─────────────────────────────────────────┘                │
└─────────────────────────────────────────────────────────────┘
```

## Components and Interfaces

### 1. URL Resolution Utility Function

在 `lib/common/utils.py` 中添加统一的 URL 解析函数：

```python
def resolve_js_url(path: str, base_url: str) -> str:
    """
    Resolve a JS path to an absolute URL.
    
    Args:
        path: The JS path (can be absolute, protocol-relative, or relative)
        base_url: The base URL for resolving relative paths
    
    Returns:
        The resolved absolute URL
    """
```

### 2. ParseJs._download_js_by_source 修改

修改路径处理逻辑，使用新的 `resolve_js_url` 函数：

```python
def _download_js_by_source(self):
    # ...
    for path in js_paths:
        path = path.strip()
        if not path:
            continue
        # 使用统一的 URL 解析函数
        real_paths.append(resolve_js_url(path, self.base_url))
```

## Data Models

无需新增数据模型，复用现有的 `DiscoverySource` 和 `JsDiscoveryRecord`。

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Absolute URL Preservation

*For any* absolute URL (starting with `http://` or `https://`) and *any* base URL, calling `resolve_js_url(absolute_url, base_url)` SHALL return the absolute URL unchanged.

**Validates: Requirements 1.1, 1.2, 2.2**

### Property 2: Protocol-Relative URL Resolution

*For any* protocol-relative URL (starting with `//`) and *any* base URL with a valid protocol, calling `resolve_js_url(protocol_relative_url, base_url)` SHALL return a URL that:
- Starts with the protocol from base_url
- Contains the rest of the protocol-relative URL unchanged

**Validates: Requirements 1.3, 2.4**

### Property 3: Relative Path Resolution

*For any* relative path (not starting with `http://`, `https://`, or `//`) and *any* valid base URL, calling `resolve_js_url(relative_path, base_url)` SHALL return the same result as `urllib.parse.urljoin(base_url, relative_path)`.

**Validates: Requirements 1.4, 2.3**

## Error Handling

1. **空路径**: 返回空字符串
2. **无效 base_url**: 对于相对路径，如果 base_url 无效，记录警告并尝试返回原始路径
3. **特殊协议**: 跳过 `javascript:`, `data:`, `about:` 等特殊协议的 URL

## 防止类似问题再次发生

### 设计原则

1. **单一职责**: URL 解析逻辑集中在 `resolve_js_url` 函数中，所有需要解析 URL 的地方都调用此函数
2. **早期检测**: 在函数入口处立即检测 URL 类型，避免不必要的处理
3. **不可变性**: 绝对 URL 永远不被修改，这是核心不变量

### 代码审查检查点

1. 任何使用 `urljoin` 的地方都应该先检查是否已经是绝对 URL
2. `IframeParser` 返回的 URL 应该已经是绝对 URL，不需要再次处理
3. 新增的 JS 发现来源必须明确其返回的是绝对 URL 还是相对路径

## Testing Strategy

### Property-Based Testing

使用 `hypothesis` 库进行属性测试，验证 `resolve_js_url` 函数的正确性。

**测试框架**: pytest + hypothesis

**测试配置**: 每个属性测试运行至少 100 次迭代

**测试文件**: `tests/test_url_resolution.py`

### Unit Tests

1. 测试绝对 URL 保持不变
2. 测试协议相对 URL 正确添加协议
3. 测试相对路径正确拼接
4. 测试边界情况（空路径、特殊字符等）

### Integration Tests

1. 端到端测试：模拟 iframe 解析流程，验证 JS 路径正确传递到下载模块
