"""
MALINFO — Script Static Analysis (PowerShell, Batch, JS/VBS, Python, Shell).

Analysis for scripting languages commonly used in malware.
Includes: AST parsing, obfuscation detection, AMSI bypass patterns, encoded commands,
download cradles, ActiveX/COM usage, eval/Function constructor, marshal/pickle.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from app.analysis.strings_entropy import shannon_entropy

logger = logging.getLogger("malinfo.script_analysis")

# ──────────────────────────────────────────────────────────────────────────────
# PowerShell Detection Patterns
# ──────────────────────────────────────────────────────────────────────────────

_PS_OBFUSCATION_PATTERNS = [
    (r"-[Ee]nc(odedCommand)?\s+", "EncodedCommand parameter"),
    (r"[Ii][Ee][Xx]\s*\(", "Invoke-Expression (IEX)"),
    (r"[Ii]nvoke\-[Ee]xpression", "Invoke-Expression full"),
    (r"[Dd]ownload[Ss]tring", "DownloadString"),
    (r"[Dd]ownload[Ff]ile", "DownloadFile"),
    (r"[Nn]ew\-[Oo]bject\s+Net\.WebClient", "Net.WebClient instantiation"),
    (r"[Nn]ew\-[Oo]bject\s+MSXML2\.XMLHTTP", "MSXML2.XMLHTTP"),
    (r"[Nn]ew\-[Oo]bject\s+System\.Net\.WebClient", "System.Net.WebClient"),
    (r"[Ss]hell\.Execute", "Shell.Execute"),
    (r"[Ww]Script\.Shell", "WScript.Shell"),
    (r"[Ww]Script\.Network", "WScript.Network"),
    (r"[Aa]DO[Dd]B\.Stream", "ADODB.Stream"),
    (r"[Ss]ystem\.Net\.WebClient", "System.Net.WebClient"),
    (r"[Ii]nvoke\-[Ww]eb[Rr]equest", "Invoke-WebRequest"),
    (r"[Ii]nvoke\-[Rr]est[Mm]ethod", "Invoke-RestMethod"),
    (r"[Ss]tart\-[Pp]rocess", "Start-Process"),
    (r"[Cc]md\.exe\s*/[Cc]", "cmd.exe /c"),
    (r"[Pp]owershell\.exe\s*-", "powershell.exe with args"),
    (r"[Bb]ypass", "ExecutionPolicy Bypass"),
    (r"[Uu]nrestricted", "ExecutionPolicy Unrestricted"),
    (r"[Hh]idden", "WindowStyle Hidden"),
    (r"[Nn]o[Pp]rofile", "NoProfile"),
    (r"[Nn]on[Ii]nteractive", "NonInteractive"),
    (r"[Ww]indow[Ss]tyle\s+Hidden", "WindowStyle Hidden"),
    (r"\$[A-Za-z0-9_]+\s*=\s*['\"][A-Za-z0-9+/]{100,}={0,2}['\"]", "Large base64 string assignment"),
    (r"[Ff]rom[Bb]ase64[Ss]tring", "FromBase64String"),
    (r"[Tt]o[Bb]ase64[Ss]tring", "ToBase64String"),
    (r"[Gg]zip|[Dd]eflate", "Compression"),
    (r"[Ii]nvoke\-[Oo]bfuscation", "Invoke-Obfuscation framework"),
    (r"[Oo]bfuscate", "Obfuscation keyword"),
    (r"[Ss]ecure[Ss]tring", "SecureString usage"),
    (r"[Pp]tr\s+ToString", "PtrToString (marshal)"),
    (r"[Mm]arshal\.", "Marshal class"),
    (r"[Rr]eflection\.", "Reflection usage"),
    (r"[Aa]pp[Dd]omain", "AppDomain"),
    (r"[Aa]ssembly\.[Ll]oad", "Assembly.Load"),
    (r"[Dd]ynamic[Ii]nvoke", "DynamicInvoke"),
    (r"[Gg]et[Dd]elegate", "GetDelegateForFunctionPointer"),
    (r"[Vv]irtual[Pp]rotect", "VirtualProtect"),
    (r"[Aa]msi\.[Uu]tils", "AMSI Utils"),
    (r"[Aa]msi[Ss]can", "AmsiScan"),
    (r"[Rr]ef\.[Aa]ssembly", "Ref.Assembly"),
    (r"[Ss]ystem\.Reflection\.Assembly", "System.Reflection.Assembly"),
]

_PS_SUSPICIOUS_KEYWORDS = [
    "Invoke-Expression", "IEX", "DownloadString", "DownloadFile",
    "Net.WebClient", "WebClient", "MSXML2.XMLHTTP", "WinHttpRequest",
    "ShellExecute", "WScript.Shell", "WScript.Network", "ADODB.Stream",
    "Invoke-WebRequest", "Invoke-RestMethod", "Start-Process",
    "bypass", "unrestricted", "hidden", "noprofile", "noninteractive",
    "FromBase64String", "ToBase64String", "Gzip", "Deflate",
    "Invoke-Obfuscation", "SecureString", "PtrToString", "Marshal",
    "Reflection", "AppDomain", "Assembly.Load", "DynamicInvoke",
    "GetDelegateForFunctionPointer", "VirtualProtect",
    "AmsiUtils", "AmsiScanBuffer", "AmsiScanString",
]

# ──────────────────────────────────────────────────────────────────────────────
# Batch/CMD Detection Patterns
# ──────────────────────────────────────────────────────────────────────────────

_BATCH_OBFUSCATION_PATTERNS = [
    (r"%\s*[A-Za-z0-9_]+\s*%", "Variable obfuscation"),
    (r"set\s+[A-Za-z0-9_]+=", "Variable assignment"),
    (r"delayedexpansion", "Delayed expansion"),
    (r"!\s*[A-Za-z0-9_]+\s*!", "Delayed expansion variable"),
    (r"for\s+/[fF]\s+", "FOR /F loop"),
    (r"for\s+/[lL]\s+", "FOR /L loop"),
    (r"findstr\s+/[rR]", "FINDSTR /R (regex)"),
    (r"certutil\s+-decode", "certutil -decode (base64)"),
    (r"powershell\s+-", "Embedded PowerShell"),
    (r"cscript\s+//[Ee]\s+", "cscript //E (engine)"),
    (r"wscript\s+//[Ee]\s+", "wscript //E"),
    (r"mshta\s+", "mshta (HTML Application)"),
    (r"rundll32\s+", "rundll32"),
    (r"regsvr32\s+/[sS]\s+/[uU]\s+/[nN]\s+/[iI]:", "regsvr32 /s /u /n /i:"),
    (r"bitsadmin\s+/transfer", "bitsadmin transfer"),
    (r"curl\s+-", "curl download"),
    (r"wget\s+-", "wget download"),
]

# ──────────────────────────────────────────────────────────────────────────────
# JavaScript/VBScript Detection Patterns
# ──────────────────────────────────────────────────────────────────────────────

_JS_OBFUSCATION_PATTERNS = [
    (r"eval\s*\(", "eval() usage"),
    (r"Function\s*\(\s*[\"']", "Function constructor"),
    (r"setTimeout\s*\(\s*[\"']", "setTimeout with string"),
    (r"setInterval\s*\(\s*[\"']", "setInterval with string"),
    (r"new\s+Function\s*\(", "new Function()"),
    (r"[\"']use strict[\"']", "Strict mode (evasion)"),
    (r"unescape\s*\(", "unescape()"),
    (r"escape\s*\(", "escape()"),
    (r"atob\s*\(", "atob() (base64 decode)"),
    (r"btoa\s*\(", "btoa() (base64 encode)"),
    (r"String\.fromCharCode", "String.fromCharCode"),
    (r"String\.fromCodePoint", "String.fromCodePoint"),
    (r"charCodeAt", "charCodeAt"),
    (r"\\x[0-9a-fA-F]{2}", "Hex escape sequences"),
    (r"\\u[0-9a-fA-F]{4}", "Unicode escape sequences"),
    (r"ActiveXObject\s*\(", "ActiveXObject"),
    (r"WScript\.Shell", "WScript.Shell"),
    (r"WScript\.Network", "WScript.Network"),
    (r"Shell\.Application", "Shell.Application"),
    (r"ADODB\.Stream", "ADODB.Stream"),
    (r"MSXML2\.XMLHTTP", "MSXML2.XMLHTTP"),
    (r"WinHttpRequest", "WinHttpRequest"),
    (r"Scripting\.FileSystemObject", "Scripting.FileSystemObject"),
    (r"Scripting\.Dictionary", "Scripting.Dictionary"),
    (r"GetObject\s*\(", "GetObject (WMI/COM)"),
    (r"CreateObject\s*\(", "CreateObject"),
    (r"WMI", "WMI usage"),
    (r"Win32_Process", "Win32_Process"),
    (r"Win32_Service", "Win32_Service"),
    (r"JSFuck", "JSFuck obfuscation"),
    (r"AAEncode", "AAEncode obfuscation"),
    (r"packer", "Packer"),
    (r"obfuscator", "Obfuscator"),
    (r"[0-9]{3,}", "Large numeric arrays (potential shellcode)"),
]

_VBS_OBFUSCATION_PATTERNS = [
    (r"Execute\s*\(", "Execute()"),
    (r"ExecuteGlobal\s*\(", "ExecuteGlobal()"),
    (r"Eval\s*\(", "Eval()"),
    (r"CreateObject\s*\(", "CreateObject"),
    (r"GetObject\s*\(", "GetObject"),
    (r"WScript\.Shell", "WScript.Shell"),
    (r"WScript\.Network", "WScript.Network"),
    (r"Shell\.Application", "Shell.Application"),
    (r"ADODB\.Stream", "ADODB.Stream"),
    (r"MSXML2\.XMLHTTP", "MSXML2.XMLHTTP"),
    (r"WinHttpRequest", "WinHttpRequest"),
    (r"Scripting\.FileSystemObject", "Scripting.FileSystemObject"),
    (r"WMI", "WMI usage"),
    (r"Win32_Process", "Win32_Process"),
    (r"Chr\s*\(", "Chr() (character obfuscation)"),
    (r"ChrW\s*\(", "ChrW()"),
    (r"Asc\s*\(", "Asc()"),
    (r"AscW\s*\(", "AscW()"),
    (r"StrReverse", "StrReverse"),
    (r"Replace\s*\(", "Replace (string manipulation)"),
    (r"Mid\s*\(", "Mid"),
    (r"Left\s*\(", "Left"),
    (r"Right\s*\(", "Right"),
]

# ──────────────────────────────────────────────────────────────────────────────
# Python Detection Patterns
# ──────────────────────────────────────────────────────────────────────────────

_PY_OBFUSCATION_PATTERNS = [
    (r"eval\s*\(", "eval()"),
    (r"exec\s*\(", "exec()"),
    (r"compile\s*\(", "compile()"),
    (r"__import__\s*\(", "__import__"),
    (r"importlib\.", "importlib"),
    (r"importlib\.import_module", "import_module"),
    (r"importlib\.util", "importlib.util"),
    (r"runpy\.", "runpy"),
    (r"subprocess\.", "subprocess"),
    (r"os\.system", "os.system"),
    (r"os\.popen", "os.popen"),
    (r"os\.exec", "os.exec"),
    (r"os\.fork", "os.fork"),
    (r"os\.spawn", "os.spawn"),
    (r"ctypes\.", "ctypes"),
    (r"ctypes\.windll", "ctypes.windll"),
    (r"ctypes\.cdll", "ctypes.cdll"),
    (r"ctypes\.CFUNCTYPE", "ctypes.CFUNCTYPE"),
    (r"base64\.", "base64"),
    (r"base64\.b64decode", "b64decode"),
    (r"base64\.b64encode", "b64encode"),
    (r"zlib\.", "zlib"),
    (r"zlib\.decompress", "zlib.decompress"),
    (r"gzip\.", "gzip"),
    (r"marshal\.", "marshal"),
    (r"marshal\.loads", "marshal.loads"),
    (r"pickle\.", "pickle"),
    (r"pickle\.loads", "pickle.loads"),
    (r"pickle\.Unpickler", "Unpickler"),
    (r"dill\.", "dill"),
    (r"cloudpickle\.", "cloudpickle"),
    (r"PyInstaller", "PyInstaller"),
    (r"py2exe", "py2exe"),
    (r"cx_Freeze", "cx_Freeze"),
    (r"nuitka", "Nuitka"),
    (r"__pycache__", "Bytecode cache"),
    (r"\.pyc", "Compiled Python"),
    (r"\.pyd", "Python DLL"),
    (r"sys\._getframe", "_getframe"),
    (r"sys\.settrace", "settrace"),
    (r"sys\.setprofile", "setprofile"),
    (r"dis\.", "dis module"),
    (r"inspect\.", "inspect"),
    (r"types\.FunctionType", "FunctionType"),
    (r"types\.CodeType", "CodeType"),
    (r"bytearray", "bytearray"),
    (r"memoryview", "memoryview"),
    (r"struct\.pack", "struct.pack"),
    (r"struct\.unpack", "struct.unpack"),
]

# ──────────────────────────────────────────────────────────────────────────────
# Shell (bash/sh) Detection Patterns
# ──────────────────────────────────────────────────────────────────────────────

_SH_OBFUSCATION_PATTERNS = [
    (r"eval\s+", "eval"),
    (r"\$\(", "Command substitution $()"),
    (r"`", "Backtick command substitution"),
    (r"base64\s+-d", "base64 decode"),
    (r"base64\s+-e", "base64 encode"),
    (r"xxd\s+-r", "xxd reverse"),
    (r"od\s+-x", "od hex dump"),
    (r"curl\s+-", "curl download"),
    (r"wget\s+-", "wget download"),
    (r"nc\s+-", "netcat"),
    (r"ncat\s+-", "ncat"),
    (r"socat\s+", "socat"),
    (r"/dev/tcp/", "/dev/tcp/ (bash TCP)"),
    (r"/dev/udp/", "/dev/udp/ (bash UDP)"),
    (r"exec\s+", "exec"),
    (r"source\s+", "source"),
    (r"\.\s+/", "dot source"),
    (r"bash\s+-c", "bash -c"),
    (r"sh\s+-c", "sh -c"),
    (r"zsh\s+-c", "zsh -c"),
    (r"python\s+-c", "python -c"),
    (r"perl\s+-e", "perl -e"),
    (r"ruby\s+-e", "ruby -e"),
    (r"php\s+-r", "php -r"),
    (r"awk\s+", "awk"),
    (r"sed\s+", "sed"),
    (r"xxd\s+", "xxd"),
    (r"openssl\s+", "openssl"),
    (r"gpg\s+", "gpg"),
    (r"tar\s+-x", "tar extract"),
    (r"gunzip", "gunzip"),
    (r"zcat", "zcat"),
    (r"bzcat", "bzcat"),
    (r"xzcat", "xzcat"),
]

# ──────────────────────────────────────────────────────────────────────────────

def analyze_script(file_path: Path) -> dict:
    """
    Analyze script file based on extension/content.
    """
    result: dict = {
        "available": True,
        "format": "unknown",
        "language": "unknown",
        "size": file_path.stat().st_size,
        "entropy": 0.0,
        "lines": 0,
        "obfuscation_indicators": [],
        "suspicious_patterns": [],
        "suspicious_keywords": [],
        "ast_info": {},
        "deobfuscation_hints": [],
        "risk_score": 0,
    }

    try:
        data = file_path.read_bytes()
        text = data.decode("utf-8", errors="ignore")
        result["entropy"] = round(shannon_entropy(data), 3)
        result["lines"] = text.count("\n") + 1
        
        # Detect language by extension and content
        ext = file_path.suffix.lower()
        language = _detect_language(ext, text)
        result["language"] = language
        result["format"] = _format_for_language(language)
        
        # Run language-specific analysis
        if language == "powershell":
            _analyze_powershell(text, result)
        elif language == "batch":
            _analyze_batch(text, result)
        elif language == "javascript":
            _analyze_javascript(text, result)
        elif language == "vbscript":
            _analyze_vbscript(text, result)
        elif language == "python":
            _analyze_python(text, result)
        elif language == "shell":
            _analyze_shell(text, result)
        else:
            _analyze_generic(text, result)
        
        # Calculate risk score
        result["risk_score"] = _calculate_script_risk(result)
        
    except Exception as exc:
        logger.debug(f"Script analysis failed: {exc}")
        return {"error": f"Failed to analyze script: {exc}", "available": False}

    return result


def _detect_language(ext: str, text: str) -> str:
    """Detect script language from extension and content."""
    ext_map = {
        ".ps1": "powershell",
        ".psm1": "powershell",
        ".psd1": "powershell",
        ".ps1xml": "powershell",
        ".bat": "batch",
        ".cmd": "batch",
        ".js": "javascript",
        ".jse": "javascript",
        ".vbs": "vbscript",
        ".vbe": "vbscript",
        ".wsf": "vbscript",
        ".hta": "javascript",
        ".py": "python",
        ".pyw": "python",
        ".sh": "shell",
        ".bash": "shell",
        ".zsh": "shell",
        ".ksh": "shell",
        ".csh": "shell",
        ".tcsh": "shell",
    }
    
    if ext in ext_map:
        return ext_map[ext]
    
    # Content-based detection
    text_lower = text.lower()
    if any(kw in text_lower for kw in ["param(", "function ", "cmdletbinding", "powershell", "get-command", "get-help"]):
        return "powershell"
    if any(kw in text_lower for kw in ["@echo off", "set ", "goto ", "call ", "if ", "for %%"]):
        return "batch"
    if any(kw in text_lower for kw in ["function ", "var ", "const ", "let ", "eval(", "document.", "window."]):
        return "javascript"
    if any(kw in text_lower for kw in ["sub ", "function ", "dim ", "set ", "createobject", "wscript."]):
        return "vbscript"
    if any(kw in text_lower for kw in ["def ", "import ", "from ", "class ", "print(", "if __name__"]):
        return "python"
    if any(kw in text_lower for kw in ["#!/bin/", "#!/usr/bin/env", "then", "fi", "done", "esac", "elif"]):
        return "shell"
    
    return "unknown"


def _format_for_language(language: str) -> str:
    formats = {
        "powershell": "PowerShell Script",
        "batch": "Batch/CMD Script",
        "javascript": "JavaScript/JScript",
        "vbscript": "VBScript",
        "python": "Python Script",
        "shell": "Shell Script (bash/sh)",
        "unknown": "Unknown Script",
    }
    return formats.get(language, "Unknown Script")


def _analyze_powershell(text: str, result: dict) -> None:
    """Analyze PowerShell script."""
    # Check for obfuscation patterns
    for pattern, desc in _PS_OBFUSCATION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            result["obfuscation_indicators"].append(desc)
    
    # Check for suspicious keywords
    for kw in _PS_SUSPICIOUS_KEYWORDS:
        if re.search(rf"\b{re.escape(kw)}\b", text, re.IGNORECASE):
            result["suspicious_keywords"].append(kw)
    
    # Check for download cradles
    cradle_patterns = [
        r"IEX\s*\(\s*New-Object\s+Net\.WebClient\s*\)\.DownloadString",
        r"Invoke-Expression\s*\(\s*New-Object\s+Net\.WebClient\s*\)\.DownloadString",
        r"iex\s*\(new-object\s+net\.webclient\)\.downloadstring",
    ]
    for cp in cradle_patterns:
        if re.search(cp, text, re.IGNORECASE):
            result["suspicious_patterns"].append("Download cradle (IEX + WebClient.DownloadString)")
            break
    
    # Check for encoded command
    if re.search(r"-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/]{50,}={0,2}", text, re.IGNORECASE):
        result["obfuscation_indicators"].append("EncodedCommand with large base64 payload")
        result["deobfuscation_hints"].append("Try: powershell -encodedcommand <payload> | decode base64")
    
    # AST parsing if available
    try:
        # Could use PowerShell's System.Management.Automation.Language.Parser
        # For now, note that AST parsing is available
        result["ast_info"]["note"] = "PowerShell AST parsing available via System.Management.Automation.Language.Parser"
    except Exception:
        pass


def _analyze_batch(text: str, result: dict) -> None:
    """Analyze Batch/CMD script."""
    for pattern, desc in _BATCH_OBFUSCATION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            result["obfuscation_indicators"].append(desc)
    
    # Check for embedded PowerShell
    if re.search(r"powershell\s+-", text, re.IGNORECASE):
        result["suspicious_patterns"].append("Embedded PowerShell command")
    
    # Check for certutil decode
    if re.search(r"certutil\s+-decode", text, re.IGNORECASE):
        result["obfuscation_indicators"].append("certutil -decode (base64 decode)")
        result["deobfuscation_hints"].append("Look for base64 data after certutil -decode")


def _analyze_javascript(text: str, result: dict) -> None:
    """Analyze JavaScript/JScript."""
    for pattern, desc in _JS_OBFUSCATION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            result["obfuscation_indicators"].append(desc)
    
    # Check for JSFuck
    if re.search(r"[\[\]\(\)\!\+\{\}]", text) and len(re.findall(r"[\[\]\(\)\!\+\{\}]", text)) > 100:
        result["obfuscation_indicators"].append("Possible JSFuck obfuscation")
    
    # Check for ActiveX/COM
    com_patterns = ["ActiveXObject", "WScript.Shell", "WScript.Network", "Shell.Application", "ADODB.Stream", "MSXML2.XMLHTTP", "WinHttpRequest"]
    for cp in com_patterns:
        if re.search(cp, text, re.IGNORECASE):
            result["suspicious_patterns"].append(f"COM/ActiveX usage: {cp}")
    
    # AST parsing
    try:
        import esprima
        ast = esprima.parseScript(text, {"tolerant": True})
        result["ast_info"]["functions"] = _count_js_functions(ast)
        result["ast_info"]["eval_calls"] = _count_js_eval(ast)
    except ImportError:
        result["ast_info"]["note"] = "esprima not installed for AST parsing"
    except Exception as exc:
        result["ast_info"]["parse_error"] = str(exc)


def _analyze_vbscript(text: str, result: dict) -> None:
    """Analyze VBScript."""
    for pattern, desc in _VBS_OBFUSCATION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            result["obfuscation_indicators"].append(desc)
    
    # Check for COM/ActiveX
    com_patterns = ["CreateObject", "GetObject", "WScript.Shell", "WScript.Network", "Shell.Application", "ADODB.Stream", "MSXML2.XMLHTTP", "WinHttpRequest"]
    for cp in com_patterns:
        if re.search(cp, text, re.IGNORECASE):
            result["suspicious_patterns"].append(f"COM/ActiveX usage: {cp}")


def _analyze_python(text: str, result: dict) -> None:
    """Analyze Python script."""
    for pattern, desc in _PY_OBFUSCATION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            result["obfuscation_indicators"].append(desc)
    
    # AST parsing
    try:
        import ast
        tree = ast.parse(text)
        result["ast_info"]["functions"] = sum(1 for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
        result["ast_info"]["classes"] = sum(1 for n in ast.walk(tree) if isinstance(n, ast.ClassDef))
        result["ast_info"]["imports"] = sum(1 for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)))
        result["ast_info"]["eval_exec"] = sum(1 for n in ast.walk(tree) if isinstance(n, (ast.Call,)) and hasattr(n.func, 'id') and n.func.id in ('eval', 'exec', 'compile'))
    except SyntaxError:
        result["ast_info"]["parse_error"] = "Syntax error in Python code"
    except Exception as exc:
        result["ast_info"]["error"] = str(exc)


def _analyze_shell(text: str, result: dict) -> None:
    """Analyze Shell script (bash/sh)."""
    for pattern, desc in _SH_OBFUSCATION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            result["obfuscation_indicators"].append(desc)
    
    # Check for reverse shell patterns
    reverse_shell_patterns = [
        r"/dev/tcp/",
        r"/dev/udp/",
        r"bash\s+-i\s*>&\s*/dev/tcp",
        r"nc\s+-e\s+/bin/sh",
        r"socat\s+",
    ]
    for rp in reverse_shell_patterns:
        if re.search(rp, text, re.IGNORECASE):
            result["suspicious_patterns"].append("Reverse shell pattern detected")


def _analyze_generic(text: str, result: dict) -> None:
    """Generic analysis for unknown scripts."""
    # Check for base64
    b64_matches = re.findall(r"[A-Za-z0-9+/]{100,}={0,2}", text)
    if b64_matches:
        result["obfuscation_indicators"].append(f"Base64 strings found ({len(b64_matches)})")
    
    # Check for hex
    hex_matches = re.findall(r"(?:0x|\\x)[0-9a-fA-F]{50,}", text)
    if hex_matches:
        result["obfuscation_indicators"].append(f"Hex strings found ({len(hex_matches)})")


def _count_js_functions(node) -> int:
    """Count function declarations in JS AST."""
    count = 0
    if hasattr(node, "type") and node.type in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
        count = 1
    for value in vars(node).values():
        if isinstance(value, list):
            for item in value:
                if hasattr(item, "type"):
                    count += _count_js_functions(item)
        elif hasattr(value, "type"):
            count += _count_js_functions(value)
    return count


def _count_js_eval(node) -> int:
    """Count eval/Function constructor calls in JS AST."""
    count = 0
    if hasattr(node, "type") and node.type == "CallExpression":
        if hasattr(node, "callee"):
            callee = node.callee
            if hasattr(callee, "name") and callee.name in ("eval", "Function", "setTimeout", "setInterval"):
                count = 1
            elif hasattr(callee, "type") and callee.type == "NewExpression":
                if hasattr(callee, "callee") and hasattr(callee.callee, "name") and callee.callee.name == "Function":
                    count = 1
    for value in vars(node).values():
        if isinstance(value, list):
            for item in value:
                if hasattr(item, "type"):
                    count += _count_js_eval(item)
        elif hasattr(value, "type"):
            count += _count_js_eval(value)
    return count


def _calculate_script_risk(result: dict) -> int:
    """Calculate risk score for script (0-100)."""
    score = 0
    
    # Obfuscation indicators
    score += len(result.get("obfuscation_indicators", [])) * 5
    
    # Suspicious patterns
    score += len(result.get("suspicious_patterns", [])) * 8
    
    # Suspicious keywords
    score += len(result.get("suspicious_keywords", [])) * 3
    
    # Language-specific bonuses
    lang = result.get("language", "")
    if lang in ("powershell", "batch") and result.get("obfuscation_indicators"):
        score += 10  # Windows scripts with obfuscation are high risk
    
    # AST eval/exec calls
    ast_info = result.get("ast_info", {})
    if ast_info.get("eval_calls", 0) > 0:
        score += ast_info["eval_calls"] * 10
    if ast_info.get("eval_exec", 0) > 0:
        score += ast_info["eval_exec"] * 10
    
    return min(100, max(0, score))


# ──────────────────────────────────────────────────────────────────────────────
# Backward Compatibility
# ──────────────────────────────────────────────────────────────────────────────

def analyze_powershell_script(file_path: Path) -> dict:
    """Analyze PowerShell script specifically."""
    return analyze_script(file_path)