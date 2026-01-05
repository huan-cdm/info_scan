# Implementation Plan

- [x] 1. Add unified URL resolution function
  - [x] 1.1 Add `resolve_js_url` function to `lib/common/utils.py`
    - Implement URL type detection (absolute, protocol-relative, relative)
    - Return absolute URLs unchanged
    - Prepend protocol for protocol-relative URLs
    - Use urljoin for relative paths
    - _Requirements: 1.2, 1.3, 1.4, 2.1_
  - [x] 1.2 Write property test for absolute URL preservation
    - **Property 1: Absolute URL Preservation**
    - **Validates: Requirements 1.1, 1.2, 2.2**
  - [x] 1.3 Write property test for protocol-relative URL resolution
    - **Property 2: Protocol-Relative URL Resolution**
    - **Validates: Requirements 1.3, 2.4**
  - [x] 1.4 Write property test for relative path resolution
    - **Property 3: Relative Path Resolution**
    - **Validates: Requirements 1.4, 2.3**

- [x] 2. Update ParseJs to use unified URL resolution
  - [x] 2.1 Modify `_download_js_by_source` method in `lib/ParseJs.py`
    - Replace inline URL handling logic with `resolve_js_url` calls
    - Ensure iframe-discovered URLs are preserved correctly
    - _Requirements: 1.1, 2.1_
  - [x] 2.2 Modify `dealJs` method to use `resolve_js_url`
    - Ensure consistency across all URL resolution paths
    - _Requirements: 2.1_

- [x] 3. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.
