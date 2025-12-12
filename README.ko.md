# block-dangerous

[Claude Code](https://docs.anthropic.com/en/docs/claude-code)용 보안 훅 스크립트로, 위험한 명령어를 차단합니다.

**[English README](./README.md)**

## 기능

- **경로 경계 보호**: 삭제 작업을 현재 프로젝트 디렉토리 내로 제한
- **`cd` 명령 추적**: `cd .. && rm -rf` 같은 경로 우회 패턴 감지
- **시스템 디렉토리 보호**: 중요 시스템 디렉토리 접근 차단 (Windows/Linux/macOS)
- **위험 패턴 감지**: 원격 코드 실행, 디스크 작업, 레지스트리 조작 등 차단
- **PowerShell 우회 방지**: .NET 및 COM 객체 기반 파일 삭제 시도 차단

## 설치

### 1. 스크립트 다운로드

```bash
# 저장소 클론
git clone https://github.com/YOUR_USERNAME/block-dangerous.git

# 또는 직접 다운로드
curl -o block-dangerous.py https://raw.githubusercontent.com/YOUR_USERNAME/block-dangerous/main/block-dangerous.py
```

### 2. 스크립트 배치

`block-dangerous.py`를 Claude 설정 디렉토리에 배치합니다:

- **Windows**: `C:\Users\<사용자명>\.claude\block-dangerous.py`
- **macOS/Linux**: `~/.claude/block-dangerous.py`

### 3. Claude Code 설정

Claude Code 설정 파일을 수정합니다:

- **Windows**: `C:\Users\<사용자명>\.claude\settings.json`
- **macOS/Linux**: `~/.claude/settings.json`

다음 훅 설정을 추가합니다:

**Windows:**
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python C:/Users/<사용자명>/.claude/block-dangerous.py"
          }
        ]
      }
    ]
  }
}
```

**macOS/Linux:**
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python ~/.claude/block-dangerous.py"
          }
        ]
      }
    ]
  }
}
```

## 작동 방식

### 경로 경계 검증

스크립트는 모든 삭제 명령어(`rm`, `del`, `rmdir`, `rd`, `Remove-Item`)를 Claude Code가 제공하는 현재 작업 디렉토리(cwd) 기준으로 검증합니다.

```
프로젝트 디렉토리: D:\projects\myapp
명령어: rm -rf ../other-folder

결과: 차단됨 (대상이 프로젝트 디렉토리 외부)
```

### `cd` 명령 추적

스크립트는 복합 명령문에서 `cd` 명령을 추적하여 실제 대상 경로를 계산합니다:

```
cwd: D:\projects\myapp
명령어: cd .. && rm -rf myapp

유효 경로: D:\projects (cd .. 이후)
대상: D:\projects\myapp
결과: 차단됨 (대상이 원본 cwd 외부)
```

### 차단 패턴

다양한 위험 패턴을 차단합니다:

| 카테고리 | 예시 |
|----------|------|
| 원격 코드 실행 | `curl ... \| bash`, `wget ... && ./script` |
| 시스템 파괴 | `mkfs.`, `dd of=/dev/`, 포크 폭탄 |
| 레지스트리 조작 | `reg delete HKLM`, `Remove-Item Registry::` |
| PowerShell 우회 | `[IO.Directory]::Delete()`, `FileSystemObject` |

## 한계

- 모든 우회 방법을 차단할 수 없음 (예: Python의 `shutil.rmtree`)
- 패턴 기반 감지의 본질적 한계 존재
- 완벽한 격리가 필요하면 컨테이너/샌드박스 환경 사용 권장

## 요구사항

- Python 3.6+
- Claude Code CLI

## 라이선스

MIT License
