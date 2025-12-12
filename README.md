# block-dangerous

A security hook script for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that blocks potentially dangerous commands.

**[한국어 README](./README.ko.md)**

## Features

- **Path Boundary Protection**: Restricts delete operations to current project directory only
- **`cd` Command Tracking**: Detects path manipulation via `cd .. && rm -rf` patterns
- **System Directory Protection**: Blocks access to critical system directories (Windows/Linux/macOS)
- **Dangerous Pattern Detection**: Blocks remote code execution, disk operations, registry manipulation, etc.
- **PowerShell Bypass Prevention**: Blocks .NET and COM object based file deletion attempts

## Installation

### 1. Download the script

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/block-dangerous.git

# Or download directly
curl -o block-dangerous.py https://raw.githubusercontent.com/YOUR_USERNAME/block-dangerous/main/block-dangerous.py
```

### 2. Place the script

Place `block-dangerous.py` in your Claude configuration directory:

- **Windows**: `C:\Users\<USERNAME>\.claude\block-dangerous.py`
- **macOS/Linux**: `~/.claude/block-dangerous.py`

### 3. Configure Claude Code settings

Edit your Claude Code settings file:

- **Windows**: `C:\Users\<USERNAME>\.claude\settings.json`
- **macOS/Linux**: `~/.claude/settings.json`

Add the following hook configuration:

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
            "command": "python C:/Users/<USERNAME>/.claude/block-dangerous.py"
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

## How It Works

### Path Boundary Validation

The script validates all delete commands (`rm`, `del`, `rmdir`, `rd`, `Remove-Item`) against the current working directory (cwd) provided by Claude Code.

```
Project directory: D:\projects\myapp
Command: rm -rf ../other-folder

Result: BLOCKED (target is outside project directory)
```

### `cd` Command Tracking

The script tracks `cd` commands in compound statements to calculate the actual target path:

```
cwd: D:\projects\myapp
Command: cd .. && rm -rf myapp

Effective path: D:\projects\myapp (after cd ..)
Target: D:\projects\myapp
Result: BLOCKED (target is outside original cwd)
```

### Protected Patterns

The script blocks various dangerous patterns including:

| Category | Examples |
|----------|----------|
| Remote Code Execution | `curl ... \| bash`, `wget ... && ./script` |
| System Destruction | `mkfs.`, `dd of=/dev/`, fork bombs |
| Registry Manipulation | `reg delete HKLM`, `Remove-Item Registry::` |
| PowerShell Bypass | `[IO.Directory]::Delete()`, `FileSystemObject` |

## Limitations

- Cannot block all possible bypass methods (e.g., Python's `shutil.rmtree`)
- Pattern-based detection has inherent limitations
- For complete isolation, consider using container/sandbox environments

## Requirements

- Python 3.6+
- Claude Code CLI

## License

MIT License
