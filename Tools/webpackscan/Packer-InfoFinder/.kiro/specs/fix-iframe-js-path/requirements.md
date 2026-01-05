# Requirements Document

## Introduction

修复 IframeParser 发现的 JS 文件路径被错误重新拼接的问题。当前实现中，iframe 内发现的 JS 文件已经被正确解析为绝对 URL，但在 `_download_js_by_source` 方法中被错误地使用主页面的 base_url 重新拼接，导致下载 404 错误。

## Glossary

- **IframeParser**: 负责递归解析 iframe/frame 标签并发现其中 JS 文件的模块
- **ParseJs**: 主解析模块，协调各种 JS 发现方式并下载 JS 文件
- **base_url**: 用于解析相对路径的基准 URL
- **绝对 URL**: 包含完整协议和域名的 URL（如 `http://example.com/js/app.js`）
- **相对路径**: 不包含协议和域名的路径（如 `js/app.js` 或 `/js/app.js`）
- **DiscoverySource**: JS 文件的发现来源枚举（STATIC_HTML, IFRAME, INLINE_PATTERN, BROWSER_INTERCEPT）

## Requirements

### Requirement 1

**User Story:** As a security researcher, I want JS files discovered in iframes to be downloaded from their correct URLs, so that I can analyze all JS resources without 404 errors.

#### Acceptance Criteria

1. WHEN IframeParser returns JS URLs THEN the ParseJs module SHALL preserve the absolute URLs without modification
2. WHEN a JS path is already an absolute URL (starting with http:// or https://) THEN the system SHALL use the URL directly without re-joining with base_url
3. WHEN a JS path is protocol-relative (starting with //) THEN the system SHALL prepend only the protocol from the current context
4. WHEN a JS path is a relative path THEN the system SHALL join it with the appropriate base_url for its discovery source

### Requirement 2

**User Story:** As a developer, I want the URL resolution logic to be centralized and consistent, so that all discovery sources handle paths correctly.

#### Acceptance Criteria

1. WHEN resolving any JS path THEN the system SHALL use a single unified URL resolution function
2. WHEN the unified resolution function receives an absolute URL THEN the function SHALL return the URL unchanged
3. WHEN the unified resolution function receives a relative path THEN the function SHALL join it with the provided base_url
4. WHEN the unified resolution function receives a protocol-relative URL THEN the function SHALL prepend the appropriate protocol

### Requirement 3

**User Story:** As a user, I want to see accurate debug information when JS downloads fail, so that I can diagnose path resolution issues.

#### Acceptance Criteria

1. WHEN a JS download fails THEN the system SHALL log the actual URL that was attempted
2. WHEN JS files are discovered from iframes THEN the log SHALL indicate the iframe source URL for debugging
