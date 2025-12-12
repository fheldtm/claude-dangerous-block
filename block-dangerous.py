#!/usr/bin/env python3
"""
Dangerous command blocker for Claude Code
Detects and blocks potentially destructive commands on different operating systems
Uses cwd-based path validation to restrict operations to current project directory
"""
import json
import sys
import re
import platform
import os


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
    # ===== 원격 코드 실행 =====
    (r"(wget|curl)\s+.*\|\s*(sh|bash|zsh|powershell|cmd)", "원격 스크립트 파이프 실행"),
    (r"(sh|bash|zsh)\s+<\(.*?(wget|curl)", "프로세스 치환으로 원격 스크립트 실행"),
    (r"(curl|wget)\s+.*&&\s*(\./|sh\s+|bash\s+|zsh\s+|chmod\s+\+x|powershell)", "다운로드 후 즉시 실행"),
    (r"(curl|wget)\s+.*;\s*(\./|sh\s+|bash\s+|zsh\s+|chmod\s+\+x|powershell)", "다운로드 후 즉시 실행"),
    (r"iex\s+\(.*?(curl|wget|Invoke-WebRequest)", "PowerShell로 원격 코드 실행"),
    (r"Invoke-Expression\s+.*?(Invoke-WebRequest|DownloadString)", "원격 코드 실행"),
    (r"DownloadString.*\|\s*iex", "원격 파일 다운로드 후 실행"),
    (r"eval.*\$\(.*?(curl|wget)", "eval로 원격 코드 실행"),
    (r"base64\s+-d.*\|\s*(sh|bash|zsh)", "base64 디코딩 후 실행"),
    (r"\|\s*xargs.*?(sh|bash|zsh)\s+-c", "xargs로 스크립트 실행"),
    (r"(source|\.)\s+<\(.*?(curl|wget)", "source로 원격 스크립트 실행"),
    (r"(python|python3|node|perl|ruby).*\$\(.*?(curl|wget)", "인터프리터로 원격 코드 실행"),
    (r"powershell\s+-EncodedCommand", "Base64 인코딩 코드 실행"),
    (r"cmd\s+/c\s+.*?(curl|wget|powershell|Invoke-WebRequest)", "cmd로 원격 코드 실행"),

    # ===== 임시 디렉토리 스크립트 실행 =====
    (r"(sh|bash|zsh)\s+/tmp/", "/tmp 스크립트 실행"),
    (r"(powershell|cmd|python).*(%TEMP%|%TMP%|%LocalAppData%[\\\/]Temp|\$env:TEMP)", "임시 디렉토리 스크립트 실행"),

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

    # 2. Split command by && or ; to check each part
    sub_commands = []
    for part in re.split(r'\s*&&\s*', command):
        sub_commands.extend(re.split(r'\s*;\s*', part))

    # 3. Track effective cwd (updated by cd commands)
    effective_cwd = cwd

    # 4. Validate delete/modification commands in each sub-command
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

        if re.match(r"^\s*(rm|del|rmdir|rd|Remove-Item)\s+", sub_cmd, re.IGNORECASE):
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
        print(json.dumps({
            "decision": "block",
            "reason": f"차단: {reason}"
        }))
        sys.exit(0)

    sys.exit(0)


if __name__ == "__main__":
    main()
