#!/usr/bin/env python3
"""
Dangerous command blocker for Claude Code
Detects and blocks potentially destructive commands on different operating systems
Uses cwd-based path validation to restrict operations to current project directory
Includes script content inspection for Claude Code analysis
"""
import json
import sys
import re
import platform
import os
import urllib.request
import urllib.error
import ssl


# ============================================================================
# Script Execution Detection
# ============================================================================

# 스크립트 실행 패턴
SCRIPT_EXECUTION_PATTERNS = [
    # bash/sh/zsh script.sh
    r"^\s*(bash|sh|zsh)\s+(.+\.sh)\s*$",
    r"^\s*(bash|sh|zsh)\s+(.+\.sh)\s+",
    # ./script.sh or /path/to/script.sh (직접 실행)
    r"^\s*(\./[^\s]+\.sh)\s*$",
    r"^\s*(\./[^\s]+\.sh)\s+",
    r"^\s*(/[^\s]+\.sh)\s*$",
    r"^\s*(/[^\s]+\.sh)\s+",
    # source script.sh or . script.sh
    r"^\s*(source|\.) +(.+\.sh)\s*$",
]


def extract_script_path(command, cwd):
    """
    Extract script path from command if it's a script execution
    Returns: (script_path, absolute_script_path) or (None, None)
    """
    command = command.strip()

    # bash/sh/zsh script.sh
    match = re.match(r"^\s*(bash|sh|zsh)\s+([^\s]+\.sh)", command)
    if match:
        script_path = match.group(2).strip('"').strip("'")
        abs_path = resolve_path_to_absolute(cwd, script_path)
        return script_path, abs_path

    # ./script.sh (직접 실행)
    match = re.match(r"^\s*(\./[^\s]+\.sh)", command)
    if match:
        script_path = match.group(1)
        abs_path = resolve_path_to_absolute(cwd, script_path)
        return script_path, abs_path

    # /absolute/path/script.sh (절대 경로 실행)
    match = re.match(r"^\s*(/[^\s]+\.sh)", command)
    if match:
        script_path = match.group(1)
        abs_path = normalize_path(script_path)
        return script_path, abs_path

    # source script.sh or . script.sh
    match = re.match(r"^\s*(source|\.) +([^\s]+\.sh)", command)
    if match:
        script_path = match.group(2).strip('"').strip("'")
        abs_path = resolve_path_to_absolute(cwd, script_path)
        return script_path, abs_path

    return None, None


def read_script_content(script_path, max_lines=50):
    """
    Read script content for inspection
    Returns: script content string or error message
    """
    try:
        # normalize path for reading
        actual_path = script_path.replace("/", os.sep) if os.name == "nt" else script_path

        if not os.path.exists(actual_path):
            return f"[파일 없음: {script_path}]"

        if not os.path.isfile(actual_path):
            return f"[파일이 아님: {script_path}]"

        with open(actual_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()

        if len(lines) > max_lines:
            content = ''.join(lines[:max_lines])
            content += f"\n... ({len(lines) - max_lines}줄 더 있음)"
        else:
            content = ''.join(lines)

        return content.strip()
    except Exception as e:
        return f"[읽기 오류: {str(e)}]"


def check_script_execution(command, cwd):
    """
    Check if command is executing a script and return content for inspection
    Returns: (should_block, message) tuple
    """
    script_path, abs_path = extract_script_path(command, cwd)

    if not script_path:
        return False, None

    # 스크립트 내용 읽기
    # abs_path는 normalized (lowercase) 되어있으므로 원본 경로 사용
    if script_path.startswith('/'):
        read_path = script_path
    elif script_path.startswith('./'):
        read_path = os.path.join(cwd, script_path[2:])
    else:
        read_path = os.path.join(cwd, script_path)

    content = read_script_content(read_path)

    message = f"""스크립트 실행 감지됨
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📄 파일: {script_path}
📍 경로: {read_path}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📝 내용:
{content}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  Claude Code: 위 스크립트 내용을 분석하여 안전한지 판단하세요.
    위험한 명령이 포함되어 있으면 실행을 거부하세요."""

    return True, message


# ============================================================================
# Remote Script Execution Detection
# ============================================================================

REMOTE_SCRIPT_PATTERNS = [
    # curl/wget ... | sh/bash
    r"(curl|wget)\s+[^\|]+\|\s*(sh|bash|zsh)",
    # curl/wget ... && (./script or sh script or chmod +x)
    r"(curl|wget)\s+.+&&\s*(\./|sh\s+|bash\s+|zsh\s+|chmod\s+\+x)",
    # curl/wget ... ; (./script or sh script or chmod +x)
    r"(curl|wget)\s+.+;\s*(\./|sh\s+|bash\s+|zsh\s+|chmod\s+\+x)",
    # sh/bash <(curl/wget ...)
    r"(sh|bash|zsh)\s+<\(.*?(curl|wget)",
    # source <(curl/wget ...)
    r"(source|\.)\s+<\(.*?(curl|wget)",
]


def extract_url_from_command(command):
    """
    Extract URL from curl/wget command
    Returns: URL string or None
    """
    # 가장 간단한 방법: URL 패턴을 직접 찾기
    url_pattern = r"['\"]?(https?://[^\s'\"|\)]+)['\"]?"

    # curl 명령에서 URL 찾기
    if re.search(r"\bcurl\b", command, re.IGNORECASE):
        match = re.search(url_pattern, command)
        if match:
            url = match.group(1).rstrip("'\"")
            # 파이프나 리다이렉션 문자 제거
            url = re.sub(r'[|><&;].*$', '', url)
            return url.strip()

    # wget 명령에서 URL 찾기
    if re.search(r"\bwget\b", command, re.IGNORECASE):
        match = re.search(url_pattern, command)
        if match:
            url = match.group(1).rstrip("'\"")
            url = re.sub(r'[|><&;].*$', '', url)
            return url.strip()

    return None


def download_remote_script(url, max_size=100000):
    """
    Download script content from URL
    Returns: (content, error_message)
    """
    try:
        # SSL context (allow self-signed for some cases)
        ctx = ssl.create_default_context()

        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (compatible; Claude-Code-Inspector/1.0)'
        })

        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            content_length = response.headers.get('Content-Length')
            if content_length and int(content_length) > max_size:
                return None, f"파일이 너무 큽니다 ({int(content_length)} bytes)"

            content = response.read(max_size).decode('utf-8', errors='replace')
            return content, None

    except urllib.error.HTTPError as e:
        return None, f"HTTP 오류: {e.code}"
    except urllib.error.URLError as e:
        return None, f"URL 오류: {e.reason}"
    except Exception as e:
        return None, f"다운로드 오류: {str(e)}"


def check_remote_script_execution(command):
    """
    Check if command is executing a remote script and download content for inspection
    Returns: (should_block, message) tuple
    """
    # Check if command matches remote script execution patterns
    is_remote_script = False
    for pattern in REMOTE_SCRIPT_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            is_remote_script = True
            break

    if not is_remote_script:
        return False, None

    # Extract URL
    url = extract_url_from_command(command)
    if not url:
        return True, """원격 스크립트 실행 감지됨
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  URL을 추출할 수 없습니다.
    스크립트를 먼저 다운로드하여 내용을 확인하세요."""

    # Download script content
    content, error = download_remote_script(url)

    if error:
        message = f"""원격 스크립트 실행 감지됨
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📄 URL: {url}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
❌ 다운로드 실패: {error}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  스크립트 내용을 확인할 수 없습니다.
    수동으로 다운로드하여 내용을 확인한 후 실행하세요:

    1. curl -sSf {url} -o /tmp/install_script.sh
    2. cat /tmp/install_script.sh  # 내용 확인
    3. chmod +x /tmp/install_script.sh && /tmp/install_script.sh"""
        return True, message

    # Truncate if too long
    lines = content.split('\n')
    if len(lines) > 80:
        display_content = '\n'.join(lines[:80])
        display_content += f"\n\n... ({len(lines) - 80}줄 더 있음)"
    else:
        display_content = content

    message = f"""원격 스크립트 실행 감지됨
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📄 URL: {url}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📝 스크립트 내용:
{display_content}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  Claude Code: 위 스크립트 내용을 분석하여 안전한지 판단하세요.

    ✅ 안전하다고 판단되면 다음 단계로 실행하세요:
    1. curl -sSf {url} -o /tmp/install_script.sh
    2. chmod +x /tmp/install_script.sh
    3. /tmp/install_script.sh

    ❌ 위험하다고 판단되면 실행을 거부하세요."""

    return True, message


# ============================================================================
# OS Detection
# ============================================================================

def get_os_type():
    """Detect operating system type"""
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    elif system == "darwin":
        return "macos"
    else:
        return "linux"


# ============================================================================
# Absolutely Dangerous Patterns (Always Block - OS Independent)
# ============================================================================

ABSOLUTE_DANGEROUS_PATTERNS = [
    # ===== 원격 코드 실행 (Windows PowerShell - 분석 어려움) =====
    (r"iex\s+\(.*?(curl|wget|Invoke-WebRequest)", "PowerShell로 원격 코드 실행"),
    (r"Invoke-Expression\s+.*?(Invoke-WebRequest|DownloadString)", "원격 코드 실행"),
    (r"DownloadString.*\|\s*iex", "원격 파일 다운로드 후 실행"),
    (r"powershell\s+-EncodedCommand", "Base64 인코딩 코드 실행"),
    (r"cmd\s+/c\s+.*?(curl|wget|powershell|Invoke-WebRequest)", "cmd로 원격 코드 실행"),

    # ===== 기타 위험한 실행 =====
    (r"eval.*\$\(.*?(curl|wget)", "eval로 원격 코드 실행"),
    (r"base64\s+-d.*\|\s*(sh|bash|zsh)", "base64 디코딩 후 실행"),
    (r"\|\s*xargs.*?(sh|bash|zsh)\s+-c", "xargs로 스크립트 실행"),
    (r"(python|python3|node|perl|ruby).*\$\(.*?(curl|wget)", "인터프리터로 원격 코드 실행"),

    # Note: curl/wget | sh, curl && ./script 등은 check_remote_script_execution()에서 처리
    # 스크립트를 다운로드하여 내용을 분석한 후 안전 여부 판단

    # ===== 시스템 레벨 파괴 =====
    (r"mkfs\.", "디스크 포맷"),
    (r"dd\s+.*of=/dev/", "디스크 직접 쓰기"),
    (r":()\s*{\s*:|:&\s*};", "Fork bomb"),
    (r"chmod\s+(-R\s+)*(777|000)\s+/", "시스템 권한 파괴"),
    (r"chown\s+.*\s+/\s*$", "시스템 소유권 변경"),
    (r">\s*/dev/sd[a-z]", "디스크 직접 덮어쓰기"),
    (r"echo\s+[a-z]\s*>\s*/proc/sysrq-trigger", "커널 패닉/재부팅"),
    (r"\|\s*tee\s+/etc/", "tee로 시스템 파일 쓰기"),
    (r"\|\s*tee\s+/dev/sd", "tee로 디스크 직접 쓰기"),

    # ===== 레지스트리/권한 조작 =====
    (r"reg\s+delete\s+(HKLM|HKEY_LOCAL_MACHINE)", "시스템 레지스트리 삭제"),
    (r"Remove-Item\s+-Path\s+(Registry::)?HKLM", "시스템 레지스트리 삭제"),
    (r"icacls\s+.*(/grant\s+Everyone:F|/reset)", "시스템 파일 권한 변경"),
    (r"takeown\s+(/F\s+)?(/R\s+)?(C:\\Windows|C:\\System32)", "시스템 소유권 변경"),

    # ===== 시스템 프로세스/서비스 =====
    (r"taskkill\s+/F\s+/IM\s+(explorer\.exe|svchost\.exe|lsass\.exe|winlogon\.exe|csrss\.exe)", "중요 시스템 프로세스 종료"),
    (r"net\s+stop\s+(WinDefend|MpsSvc|SecurityHealthService|wscsvc)", "Windows 보안 서비스 비활성화"),
    (r"Stop-Service\s+-(Name|DisplayName)\s+(WinDefend|MpsSvc|SecurityHealthService)", "Windows 보안 서비스 비활성화"),

    # ===== 부팅 파일 =====
    (r"del.*boot\.ini|ntldr|bootmgr|BCD", "부팅 파일 삭제"),
    (r"(rmdir|rd).*\$Recycle\.Bin", "휴지통 디렉토리 삭제"),

    # ===== 기타 우회 패턴 =====
    (r"wmic\s+.*delete|wmic\s+.*set\s+.*=.*1\s*$", "WMI로 시스템 설정 변경"),
    (r"(gpedit|gpupdate|secedit)", "Group Policy 설정 변경"),

    # ===== PowerShell .NET/COM 우회 차단 =====
    (r"\[System\.IO\.Directory\]::Delete", ".NET으로 디렉토리 삭제 시도"),
    (r"\[IO\.Directory\]::Delete", ".NET으로 디렉토리 삭제 시도"),
    (r"\[System\.IO\.File\]::Delete", ".NET으로 파일 삭제 시도"),
    (r"\[IO\.File\]::Delete", ".NET으로 파일 삭제 시도"),
    (r"FileSystemObject\)\.DeleteFolder", "COM으로 폴더 삭제 시도"),
    (r"FileSystemObject\)\.DeleteFile", "COM으로 파일 삭제 시도"),
    (r"Scripting\.FileSystemObject", "FileSystemObject COM 객체 사용"),
]


# ============================================================================
# Absolutely Protected Directories
# ============================================================================

ABSOLUTELY_PROTECTED_DIRS_LINUX = [
    "/",
    "/bin", "/sbin", "/lib", "/lib64",
    "/usr", "/usr/bin", "/usr/sbin", "/usr/lib",
    "/etc", "/etc/passwd", "/etc/shadow",
    "/sys", "/proc", "/dev",
    "/var", "/var/log",
    "/boot", "/root",
]

ABSOLUTELY_PROTECTED_DIRS_WINDOWS = [
    "C:\\",
    "C:\\Windows",
    "C:\\System32",
    "C:\\SysWOW64",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData",
    "C:\\Boot",
    "C:\\Recovery",
    "C:\\$Recycle.Bin",
]

ABSOLUTELY_PROTECTED_DIRS_MACOS = [
    "/",
    "/bin", "/sbin", "/lib",
    "/usr/bin", "/usr/sbin", "/usr/lib",
    "/etc", "/var", "/System",
    "/Library",
]


# ============================================================================
# Helper Functions
# ============================================================================

def normalize_path(path):
    """Normalize path for comparison (handle both / and \\ separators)"""
    normalized = path.replace("\\", "/")
    if normalized != "/":  # 루트 디렉토리는 유지
        normalized = normalized.rstrip("/")
    return normalized.lower()


def is_absolute_path(path):
    """Check if path is absolute (Windows or Linux)"""
    path = path.strip()
    if len(path) >= 2 and path[1] == ":" and path[0].isalpha():
        return True
    if path.startswith("/"):
        return True
    return False


def resolve_path_to_absolute(cwd, target_path):
    """
    Resolve target path to absolute path
    cwd: current working directory (absolute)
    target_path: target path (can be relative or absolute)
    Returns: absolute path (normalized)
    """
    target_path = target_path.strip()

    if is_absolute_path(target_path):
        return normalize_path(os.path.normpath(target_path))

    if cwd:
        combined = os.path.join(cwd, target_path)
        return normalize_path(os.path.normpath(combined))

    return normalize_path(target_path)


def is_within_cwd(target_path, cwd):
    """Check if target_path is within cwd directory"""
    if not cwd:
        return False

    target_normalized = normalize_path(target_path)
    cwd_normalized = normalize_path(cwd)

    return target_normalized == cwd_normalized or target_normalized.startswith(cwd_normalized + "/")


def is_absolutely_protected(target_path, os_type):
    """Check if target_path is in absolutely protected directories"""
    target_normalized = normalize_path(target_path)

    if os_type == "windows":
        protected_dirs = ABSOLUTELY_PROTECTED_DIRS_WINDOWS
    elif os_type == "macos":
        protected_dirs = ABSOLUTELY_PROTECTED_DIRS_MACOS
    else:
        protected_dirs = ABSOLUTELY_PROTECTED_DIRS_LINUX

    for protected_dir in protected_dirs:
        protected_normalized = normalize_path(protected_dir)
        if target_normalized == protected_normalized or target_normalized.startswith(protected_normalized + "/"):
            return True

    return False


def extract_target_path_from_command(command):
    """
    Extract target path from delete/modification commands
    Handles: del, rm, rmdir, rd, Remove-Item, etc.
    """
    target = None

    # rm -rf /path/to/file
    rm_match = re.match(r"^\s*rm\s+(-[rf]+\s+)*(.+)$", command)
    if rm_match:
        target = rm_match.group(2).split()[0]

    # del /s /q C:\path
    if not target:
        del_match = re.match(r"^\s*del\s+(/[sq]\s+)*(.+)$", command, re.IGNORECASE)
        if del_match:
            target = del_match.group(2).split()[0]

    # rmdir /s /q C:\path
    if not target:
        rmdir_match = re.match(r"^\s*(rmdir|rd)\s+(/[sq]\s+)*(.+)$", command, re.IGNORECASE)
        if rmdir_match:
            target = rmdir_match.group(3).split()[0]

    # Remove-Item -Path C:\path
    if not target:
        remove_match = re.match(r"^\s*Remove-Item\s+.*?-Path\s+(.+?)(?:\s+-|$)", command, re.IGNORECASE)
        if remove_match:
            target = remove_match.group(1).strip()

    # find /path -delete
    if not target:
        find_match = re.match(r"^\s*find\s+(.+?)\s+.*-delete", command, re.IGNORECASE)
        if find_match:
            target = find_match.group(1).split()[0]

    # gio trash /path
    if not target:
        gio_match = re.match(r"^\s*gio\s+trash\s+(.+)$", command, re.IGNORECASE)
        if gio_match:
            target = gio_match.group(1).split()[0]

    # git clean -fd /path or git clean -f /path (in specified directory)
    if not target:
        git_match = re.match(r"^\s*git\s+clean\s+(-[fdDx]+\s+)*(.+)?", command, re.IGNORECASE)
        if git_match:
            path_part = git_match.group(2)
            if path_part:
                target = path_part.split()[0]
            else:
                # git clean without explicit path - affects current directory
                # We'll mark this as "." to be resolved against cwd
                target = "."

    if target:
        target = target.strip('"').strip("'")

    return target


# ============================================================================
# Main Checker
# ============================================================================

def check_command(command, cwd):
    """
    Main command checker
    Returns: error message if blocked, None if allowed
    """
    os_type = get_os_type()

    # 1. Check absolutely dangerous patterns
    for pattern, message in ABSOLUTE_DANGEROUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return message

    # 1b. Check remote script execution (curl | sh, wget && ./script, etc.)
    # 이 패턴들은 스크립트를 다운로드하여 내용을 분석한 후 안내함
    is_remote, remote_message = check_remote_script_execution(command)
    if is_remote:
        return remote_message

    # 2. Split command by && or ; to check each part
    sub_commands = []
    for part in re.split(r'\s*&&\s*', command):
        sub_commands.extend(re.split(r'\s*;\s*', part))

    # 3. Track effective cwd (updated by cd commands)
    effective_cwd = cwd

    # 4. Validate each sub-command
    for sub_cmd in sub_commands:
        sub_cmd = sub_cmd.strip()
        if not sub_cmd:
            continue

        # Check for cd command and update effective_cwd
        cd_match = re.match(r"^\s*cd\s+(.+)$", sub_cmd, re.IGNORECASE)
        if cd_match:
            cd_target = cd_match.group(1).strip().strip('"').strip("'")
            effective_cwd = resolve_path_to_absolute(effective_cwd, cd_target)
            if get_os_type() == "windows":
                effective_cwd = effective_cwd.replace("/", "\\")
                if len(effective_cwd) >= 2 and effective_cwd[1] == ":":
                    effective_cwd = effective_cwd[0].upper() + effective_cwd[1:]
            continue

        # 4a. Check for script execution (스크립트 실행 검사)
        is_script, script_message = check_script_execution(sub_cmd, effective_cwd)
        if is_script:
            return script_message

        # 4b. Check delete/modification commands
        if re.match(r"^\s*(rm|del|rmdir|rd|Remove-Item|find|gio|git\s+clean)\s+", sub_cmd, re.IGNORECASE):
            target_path = extract_target_path_from_command(sub_cmd)

            if not target_path:
                return "대상 경로를 지정해주세요"

            if not effective_cwd:
                return "현재 작업 디렉토리를 확인할 수 없습니다"

            # Resolve to absolute path using effective_cwd (after cd commands)
            abs_target = resolve_path_to_absolute(effective_cwd, target_path)

            # Check against absolutely protected directories
            if is_absolutely_protected(abs_target, os_type):
                return "보호된 시스템 디렉토리는 접근할 수 없습니다"

            # Check against ORIGINAL cwd boundary (not effective_cwd)
            if not is_within_cwd(abs_target, cwd):
                return "현재 프로젝트 디렉토리 범위를 벗어났습니다"

    return None


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    cwd = input_data.get("cwd", "")
    tool_input = input_data.get("tool_input", {})
    command = tool_input.get("command", "")

    reason = check_command(command, cwd)

    if reason:
        # 스크립트 분석 정보인 경우 (차단하지 않고 정보만 전달)
        if "스크립트 내용을 분석하여 안전한지 판단하세요" in reason:
            print(json.dumps({
                "decision": "allow",
                "reason": reason
            }))
            sys.exit(0)

        # 그 외는 차단
        print(json.dumps({
            "decision": "block",
            "reason": f"차단: {reason}"
        }))
        sys.exit(0)

    sys.exit(0)


if __name__ == "__main__":
    main()
