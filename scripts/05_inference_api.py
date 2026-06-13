#!/usr/bin/env python3
"""
05_inference_api.py — Hybrid Java webshell detector: ML + rule-based.

ML layer: ResNet50 (model_best.pt) or XGBoost (xgb_model.pkl), auto-detected
  by file extension.  ResNet50 takes priority if model_best.pt is present.
Rule layer (c0ny1-derived): servlet/filter/listener interfaces, exec/reflect
  patterns, suspicious class names, missing SourceFile attribute.

Detection paths:
  fileless  (injection interface detected) → rules-first
    CONFIRMED  rule HIGH
    HIGH       rule MEDIUM
    MEDIUM     ML >= any threshold (ML less reliable on fileless)
    BENIGN     neither

  file_based (no injection interface)      → ML-first
    CONFIRMED  ML >= HIGH_THRESHOLD
    HIGH       ML >= inf_threshold
    MEDIUM     rule HIGH or MEDIUM (rule less targeted for file-based)
    BENIGN     neither

POST /predict  multipart: file=<.class bytes>
GET  /threshold
"""

import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import numpy as np

# ---------------------------------------------------------------------------
# Paths — ResNet50 (model_best.pt) takes priority over XGBoost (xgb_model.pkl)
# ---------------------------------------------------------------------------
ROOT       = Path(__file__).parent.parent
VOCAB_JSON = ROOT / "output" / "vocab.json"
LOG_PATH   = ROOT / "output" / "detections.jsonl"

_RESNET_PATH = ROOT / "output" / "model_best.pt"
_XGB_PATH    = ROOT / "output" / "xgb_model.pkl"

# Pick model automatically: ResNet50 if model_best.pt exists, else XGBoost
MODEL_PATH = _RESNET_PATH if _RESNET_PATH.exists() else _XGB_PATH

HIGH_THRESHOLD = 0.85


def _report_path() -> Path:
    return ROOT / "output" / "training_report.json" if MODEL_PATH == _RESNET_PATH \
        else ROOT / "output" / "xgb_report.json"


def load_inference_threshold() -> float:
    try:
        return float(json.loads(_report_path().read_text()).get("inference_threshold", 0.50))
    except Exception:
        return 0.50

# ---------------------------------------------------------------------------
# Opcode normalisation (must match 03_build_grayscale.py / 04b exactly)
# ---------------------------------------------------------------------------
OPCODE_NORM: dict[str, str] = {
    **{f"iconst_{s}": "iconst" for s in ["m1", "0", "1", "2", "3", "4", "5"]},
    **{f"lconst_{i}": "lconst" for i in range(2)},
    **{f"fconst_{i}": "fconst" for i in range(3)},
    **{f"dconst_{i}": "dconst" for i in range(2)},
    **{f"iload_{i}":  "iload"  for i in range(4)},
    **{f"lload_{i}":  "lload"  for i in range(4)},
    **{f"fload_{i}":  "fload"  for i in range(4)},
    **{f"dload_{i}":  "dload"  for i in range(4)},
    **{f"aload_{i}":  "aload"  for i in range(4)},
    **{f"istore_{i}": "istore" for i in range(4)},
    **{f"lstore_{i}": "lstore" for i in range(4)},
    **{f"fstore_{i}": "fstore" for i in range(4)},
    **{f"dstore_{i}": "dstore" for i in range(4)},
    **{f"astore_{i}": "astore" for i in range(4)},
}
_OPCODE_RE  = re.compile(r"^\s+\d+:\s+([a-z][a-z0-9_]+)")
INVOKE_OPS  = {"invokevirtual","invokespecial","invokestatic","invokeinterface","invokedynamic"}
REFLECT_OPS = {"invokevirtual","invokedynamic"}

# ---------------------------------------------------------------------------
# Feature extraction — shared disassembly step used by both model backends
# ---------------------------------------------------------------------------

def disassemble(class_path: Path) -> tuple[list[str], str] | tuple[None, str]:
    try:
        r = subprocess.run(
            ["javap", "-c", "-p", "-verbose", str(class_path)],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0:
            return None, ""
        ops = []
        for line in r.stdout.splitlines():
            m = _OPCODE_RE.match(line)
            if m:
                ops.append(OPCODE_NORM.get(m.group(1), m.group(1)))
        return ops, r.stdout
    except Exception:
        return None, ""


def build_adjacency_image(ops: list[str], vocab: dict[str, int]):
    """Build 149×149 opcode adjacency matrix and return as PIL grayscale Image.
    Used by the ResNet50 backend (matches 03_build_grayscale.py exactly).
    """
    from PIL import Image as PILImage
    n = len(vocab)
    mat = np.zeros((n, n), dtype=np.uint32)
    for i in range(len(ops) - 1):
        a = vocab.get(ops[i], -1)
        b = vocab.get(ops[i + 1], -1)
        if a >= 0 and b >= 0:
            mat[a, b] += 1
    max_val = mat.max()
    if max_val > 0:
        mat = (mat.astype(float) / max_val * 255).astype(np.uint8)
    else:
        mat = mat.astype(np.uint8)
    return PILImage.fromarray(mat)


def extract_xgb_features(ops: list[str], javap_text: str,
                          class_path: Path, vocab: dict[str, int]) -> np.ndarray:
    """Flat unigram + bigram + metadata feature vector for XGBoost."""
    n     = len(vocab)
    total = len(ops)

    unigram = np.zeros(n, dtype=np.float32)
    for op in ops:
        idx = vocab.get(op, -1)
        if idx >= 0:
            unigram[idx] += 1
    unigram /= total

    bigram = np.zeros(n * n, dtype=np.float32)
    for i in range(len(ops) - 1):
        a = vocab.get(ops[i], -1)
        b = vocab.get(ops[i + 1], -1)
        if a >= 0 and b >= 0:
            bigram[a * n + b] += 1
    bigram /= max(total - 1, 1)

    SERVLET_IFACES = {
        "javax/servlet/Filter", "javax/servlet/Servlet", "javax/servlet/http/HttpServlet",
        "javax/servlet/ServletRequestListener", "javax/servlet/http/HttpSessionListener",
        "jakarta/servlet/Filter", "jakarta/servlet/Servlet", "jakarta/servlet/http/HttpServlet",
    }
    invoke_cnt  = sum(1 for op in ops if op in INVOKE_OPS)
    reflect_cnt = sum(1 for op in ops if op in REFLECT_OPS)
    athrow_cnt  = ops.count("athrow")
    meta = np.array([
        min(total / 1000.0, 1.0),
        float("SourceFile:" in javap_text),
        float("$" in class_path.stem),
        float(any(iface in javap_text for iface in SERVLET_IFACES)),
        float("java/lang/Runtime" in javap_text),
        float("defineClass" in javap_text),
        float("java/net/URLClassLoader" in javap_text),
        invoke_cnt  / total,
        reflect_cnt / total,
        athrow_cnt  / total,
    ], dtype=np.float32)

    return np.concatenate([unigram, bigram, meta])

# ---------------------------------------------------------------------------
# Rule-based layer (c0ny1-inspired: expanded interface coverage + scoring)
# ---------------------------------------------------------------------------

# Servlet/Filter/Listener — direct HTTP request handling (score: 3 each)
_IFACES_SERVLET = {
    "javax/servlet/Filter", "javax/servlet/Servlet", "javax/servlet/http/HttpServlet",
    "javax/servlet/ServletRequestListener", "javax/servlet/http/HttpSessionListener",
    "javax/servlet/ServletContextListener",
    "jakarta/servlet/Filter", "jakarta/servlet/Servlet", "jakarta/servlet/http/HttpServlet",
    "jakarta/servlet/ServletContextListener", "jakarta/servlet/http/HttpSessionListener",
}

# Tomcat pipeline injection — Valve and Executor (score: 3 each)
_IFACES_TOMCAT = {
    "org/apache/catalina/Valve",
    "org/apache/catalina/valves/ValveBase",
    "org/apache/catalina/Executor",
}

# Spring/framework interceptor injection (score: 3 each)
_IFACES_SPRING = {
    "org/springframework/web/servlet/HandlerInterceptor",
    "org/springframework/web/socket/WebSocketHandler",
}

# WebSocket / Netty endpoint injection (score: 2 each)
_IFACES_WEBSOCKET = {
    "javax/websocket/Endpoint",
    "javax/websocket/server/ServerEndpointConfig$Configurator",
    "org/springframework/web/socket/WebSocketHandler",
    "io/netty/channel/ChannelHandler",
    "io/netty/channel/ChannelInboundHandler",
}

# Java Agent — ClassFileTransformer used for agentmain injection (score: 3)
_IFACES_AGENT = {
    "java/lang/instrument/ClassFileTransformer",
}

# Dangerous API calls: (regex, label, score)
# Phase 3: added Proxy, in-memory compile, BCEL, Javassist, RMI (copagent-derived)
_DANGER_APIS: list[tuple] = [
    (re.compile(r"java/lang/Runtime",               re.I), "runtime_exec",      3),
    (re.compile(r"ProcessBuilder",                  re.I), "processbuilder",    3),
    (re.compile(r"defineClass",                     re.I), "defineClass",       3),
    (re.compile(r"java/net/URLClassLoader",         re.I), "url_classloader",   2),
    (re.compile(r"sun/misc/Unsafe",                 re.I), "unsafe_api",        2),
    (re.compile(r"javax/script/ScriptEngine",       re.I), "script_engine",     2),
    (re.compile(r"groovy/lang/GroovyClassLoader",   re.I), "groovy_cl",         2),
    (re.compile(r"java/lang/instrument/Instrumentation", re.I), "agent_api",    2),
    (re.compile(r"setContextClassLoader",           re.I), "cl_hijack",         2),
    (re.compile(r"setAccessible",                   re.I), "reflection_bypass", 1),
    (re.compile(r"java/lang/reflect/Proxy",         re.I), "reflect_proxy",     2),
    (re.compile(r"javax/tools/JavaCompiler",        re.I), "in_memory_compile", 3),
    (re.compile(r"javassist/ClassPool|javassist/CtClass", re.I), "javassist",   2),
    (re.compile(r"org/apache/bcel",                 re.I), "bcel_codegen",      2),
    (re.compile(r"java/rmi/server/UnicastRemoteObject", re.I), "rmi_backdoor",  2),
]

# Known webshell tool strings in constant pool (score: 4)
_TOOL_RE = re.compile(
    r"godzilla|behinder|icescorpion|regeorg|antsword|rebeyond|"
    r"memshell|x-cmd|xpassword|java-memshell",
    re.IGNORECASE,
)

# Suspicious class name keywords (score: 2 each)
_SUSPICIOUS_KEYWORDS = [
    "shell", "cmd", "exec", "backdoor", "payload", "webshell",
    "memshell", "inject", "exploit", "hack", "evil",
    "godzilla", "behinder", "regeorg", "icescorpion",
]


def rule_check(class_path: Path, javap_text: str) -> dict:
    rules: list[str] = []
    score = 0

    # 1. Injection interface matching
    for iface in _IFACES_SERVLET:
        if iface in javap_text:
            rules.append(f"iface:{iface.split('/')[-1]}")
            score += 3
    for iface in _IFACES_TOMCAT:
        if iface in javap_text:
            rules.append(f"iface:{iface.split('/')[-1]}")
            score += 3
    for iface in _IFACES_SPRING:
        if iface in javap_text:
            rules.append(f"iface:{iface.split('/')[-1]}")
            score += 3
    for iface in _IFACES_WEBSOCKET:
        if iface in javap_text:
            rules.append(f"iface:{iface.split('/')[-1]}")
            score += 2
    for iface in _IFACES_AGENT:
        if iface in javap_text:
            rules.append(f"iface:{iface.split('/')[-1]}")
            score += 3

    # 2. Dangerous API patterns
    for pat, label, pts in _DANGER_APIS:
        if pat.search(javap_text):
            rules.append(f"api:{label}")
            score += pts

    # 3. Known tool fingerprints in constant pool
    m = _TOOL_RE.search(javap_text)
    if m:
        rules.append(f"tool:{m.group()[:20]}")
        score += 4

    # 4. Suspicious class name
    stem = class_path.stem.lower()
    for kw in _SUSPICIOUS_KEYWORDS:
        if kw in stem:
            rules.append(f"name:{kw}")
            score += 2
            break  # one match is enough

    # 5. Obfuscated class name (1-3 chars, not inner class)
    if len(class_path.stem) <= 3 and "$" not in class_path.stem:
        rules.append("name:obfuscated_short")
        score += 1

    # 6. Missing SourceFile — injected/generated classes often lack debug info
    if "SourceFile:" not in javap_text and "$" not in class_path.stem:
        rules.append("no_source_attr")
        score += 1

    if not rules:
        return {"triggered": False, "rules": [], "risk": "LOW", "score": 0}

    risk = "HIGH" if score >= 6 else "MEDIUM"
    return {"triggered": True, "rules": rules, "risk": risk, "score": score}

# ---------------------------------------------------------------------------
# Combined verdict
# ---------------------------------------------------------------------------

def combined_verdict(ml_score: float, rule: dict, inf_threshold: float) -> tuple[str, str, str]:
    """Returns (verdict, tier, detection_path).

    detection_path: 'fileless'   — injection interface rule fired, rules lead
                    'file_based' — no interface detected, ML leads
    """
    rule_high   = rule["triggered"] and rule["risk"] == "HIGH"
    rule_medium = rule["triggered"] and rule["risk"] == "MEDIUM"
    ml_high     = ml_score >= HIGH_THRESHOLD
    ml_medium   = ml_score >= inf_threshold

    # Fileless indicator: injection interface AND at least one dangerous API.
    # Interface alone is not enough — legitimate web framework classes (Tomcat,
    # Spring) implement Filter/Servlet/Listener without any malicious APIs.
    # Requiring both prevents FPs when statically scanning a full application.
    has_iface     = any(r.startswith("iface:")  for r in rule.get("rules", []))
    has_dangerapi = any(r.startswith("api:")    for r in rule.get("rules", []))
    has_tool      = any(r.startswith("tool:")   for r in rule.get("rules", []))
    fileless_path = has_iface and (has_dangerapi or has_tool)

    if fileless_path:
        # Rules-first: rule engine has 0 FP on benign_test for fileless vectors;
        # ML recall on fileless is poor (0.325) so ML only provides a MEDIUM floor.
        if rule_high:
            return "WEBSHELL", "CONFIRMED", "fileless"
        if rule_medium:
            return "WEBSHELL", "HIGH", "fileless"
        if ml_high or ml_medium:
            return "WEBSHELL", "MEDIUM", "fileless"
        return "BENIGN", "BENIGN", "fileless"

    if has_iface and not (has_dangerapi or has_tool):
        # Interface only — legitimate framework class, let ML decide
        if ml_high:
            return "WEBSHELL", "HIGH", "fileless"
        if ml_medium:
            return "WEBSHELL", "MEDIUM", "fileless"
        return "BENIGN", "BENIGN", "fileless"
    else:
        # ML-first: ResNet50 F1=0.991 on file-based webshells; rules supplement
        # when ML score falls below threshold.
        if ml_high:
            return "WEBSHELL", "CONFIRMED", "file_based"
        if ml_medium:
            return "WEBSHELL", "HIGH", "file_based"
        if rule_high or rule_medium:
            return "WEBSHELL", "MEDIUM", "file_based"
        return "BENIGN", "BENIGN", "file_based"

# ---------------------------------------------------------------------------
# Predictor — auto-detects ResNet50 vs XGBoost from MODEL_PATH extension
# ---------------------------------------------------------------------------

class Predictor:
    def __init__(self):
        self.vocab         = json.loads(VOCAB_JSON.read_text())
        self.inf_threshold = load_inference_threshold()

        if MODEL_PATH.suffix == ".pt":
            self._init_resnet50()
        else:
            self._init_xgboost()

        print(f"  Inference threshold : {self.inf_threshold:.4f}")
        print(f"  HIGH threshold      : {HIGH_THRESHOLD:.2f}")

    def _init_resnet50(self):
        import torch
        import torch.nn as nn
        import torchvision.models as models
        import torchvision.transforms as transforms

        print(f"Loading ResNet50 model from {MODEL_PATH}")
        self.backend = "resnet50"
        self.device  = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        model = models.resnet50()
        model.fc = nn.Linear(model.fc.in_features, 1)
        state = torch.load(MODEL_PATH, map_location=self.device, weights_only=True)
        model.load_state_dict(state)
        model.eval()
        self.model = model.to(self.device)

        self.transform = transforms.Compose([
            transforms.Grayscale(num_output_channels=3),
            transforms.Resize((224, 224)),
            transforms.ToTensor(),
            transforms.Normalize(mean=[0.485, 0.456, 0.406],
                                 std=[0.229, 0.224, 0.225]),
        ])
        print(f"  Backend : ResNet50  |  Device: {self.device}")

    def _init_xgboost(self):
        import joblib
        from scipy.sparse import csr_matrix as _csr
        self._csr = _csr

        print(f"Loading XGBoost model from {MODEL_PATH}")
        self.backend = "xgboost"
        self.model   = joblib.load(MODEL_PATH)
        print(f"  Backend : XGBoost")

    def _ml_score(self, class_path: Path, ops: list[str], javap_text: str) -> float:
        if self.backend == "resnet50":
            import torch
            img    = build_adjacency_image(ops, self.vocab)
            tensor = self.transform(img).unsqueeze(0).to(self.device)
            with torch.no_grad():
                return float(torch.sigmoid(self.model(tensor)).item())
        else:
            feats = extract_xgb_features(ops, javap_text, class_path, self.vocab)
            return float(self.model.predict_proba(self._csr(feats.reshape(1, -1)))[0, 1])

    def predict_from_javap(self, name_path: Path, javap_text: str) -> dict:
        """Run the full ML+rule pipeline on pre-computed javap output.
        Used for JSP analysis where the .class stays inside the Docker container."""
        ops = []
        for line in javap_text.splitlines():
            m = _OPCODE_RE.match(line)
            if m:
                ops.append(OPCODE_NORM.get(m.group(1), m.group(1)))

        if not ops:
            rule = rule_check(name_path, javap_text)
            if rule["triggered"]:
                verdict, tier, dpath = combined_verdict(0.0, rule, self.inf_threshold)
                return {"verdict": verdict, "tier": tier, "detection_path": dpath,
                        "ml_score": None, "rule": rule, "backend": self.backend}
            return {"verdict": "BENIGN", "tier": "BENIGN", "detection_path": "interface",
                    "ml_score": None, "rule": rule_check(name_path, javap_text),
                    "backend": self.backend}

        if len(ops) < 4:
            rule = rule_check(name_path, javap_text)
            if rule["triggered"]:
                verdict, tier, dpath = combined_verdict(0.0, rule, self.inf_threshold)
                return {"verdict": verdict, "tier": tier, "detection_path": dpath,
                        "ml_score": None, "rule": rule, "backend": self.backend}
            return {"verdict": "BENIGN", "tier": "BENIGN", "detection_path": "interface",
                    "ml_score": None, "rule": rule, "backend": self.backend}

        ml_score            = self._ml_score(name_path, ops, javap_text)
        rule                = rule_check(name_path, javap_text)
        verdict, tier, path = combined_verdict(ml_score, rule, self.inf_threshold)
        return {"verdict": verdict, "tier": tier, "detection_path": path,
                "ml_score": round(ml_score, 4), "rule": rule, "backend": self.backend}

    def predict(self, class_path: Path) -> dict:
        ops, javap_text = disassemble(class_path)

        if ops is None:
            return {
                "verdict": "ERROR", "tier": "ERROR",
                "ml_score": None,
                "rule": {"triggered": False, "rules": [], "risk": "LOW"},
                "reason": "javap failed",
                "description": "Analysis error",
            }

        if len(ops) < 4:
            rule = rule_check(class_path, javap_text)
            if rule["triggered"]:
                verdict, tier, dpath = combined_verdict(0.0, rule, self.inf_threshold)
                r = {"verdict": verdict, "tier": tier, "detection_path": dpath,
                     "ml_score": None, "rule": rule, "backend": self.backend}
            else:
                r = {"verdict": "BENIGN", "tier": "BENIGN", "detection_path": "interface",
                     "ml_score": None, "rule": rule, "backend": self.backend}
            r["description"] = describe_shell(r)
            return r

        ml_score            = self._ml_score(class_path, ops, javap_text)
        rule                = rule_check(class_path, javap_text)
        verdict, tier, path = combined_verdict(ml_score, rule, self.inf_threshold)

        r = {
            "verdict":        verdict,
            "tier":           tier,
            "detection_path": path,
            "ml_score":       round(ml_score, 4),
            "rule":           rule,
            "backend":        self.backend,
        }
        r["description"] = describe_shell(r)
        return r

# ---------------------------------------------------------------------------
# JSP compilation helper
# ---------------------------------------------------------------------------

_JSP_COMPILER_MOD = None   # cached so _TOMCAT_READY flag persists across calls

def _load_jsp_compiler():
    global _JSP_COMPILER_MOD
    if _JSP_COMPILER_MOD is None:
        spec = importlib.util.spec_from_file_location(
            "compile_jsp", Path(__file__).parent / "compile_jsp.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _JSP_COMPILER_MOD = mod
    return _JSP_COMPILER_MOD.compile_jsp


# Imports that are standard Java/Servlet/JSTL — not interesting to report
_STANDARD_IMPORT_PREFIXES = (
    "java.", "javax.", "jakarta.", "org.w3c.", "org.xml.", "sun.",
)

_IMPORT_RE = re.compile(
    r'<%@\s*page\b[^%]*\bimport\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE | re.DOTALL,
)


def _extract_imports(src: str) -> list[str]:
    """Return non-standard imports from <%@ page import="..." %> directives."""
    imports: list[str] = []
    for m in _IMPORT_RE.finditer(src):
        for cls in m.group(1).split(","):
            cls = cls.strip().rstrip("*").rstrip(".")
            if cls and not any(cls.startswith(p) for p in _STANDARD_IMPORT_PREFIXES):
                imports.append(cls)
    return sorted(set(imports))


def _normalize_escapes(src: str) -> str:
    """Resolve Java/JSP Unicode (\\uXXXX) and octal (\\NNN) escapes so pattern
    matching works even on heavily obfuscated source."""
    # Unicode escapes
    src = re.sub(
        r'\\u([0-9a-fA-F]{4})',
        lambda m: chr(int(m.group(1), 16)),
        src,
    )
    # Octal escapes inside string literals (0–127 only to avoid false matches)
    src = re.sub(
        r'\\([0-7]{1,3})',
        lambda m: chr(int(m.group(1), 8)) if int(m.group(1), 8) < 128 else m.group(0),
        src,
    )
    return src


_SRC_PATTERNS: list[tuple] = [
    # Command execution — catches both chained and two-statement forms:
    #   Runtime.getRuntime().exec(...)
    #   Runtime run = Runtime.getRuntime(); run.exec(...)
    (re.compile(r"Runtime\.getRuntime\(\)\.exec|Runtime\.exec\b|getRuntime\s*\(\s*\)", re.I), "api:runtime_exec", 3),
    (re.compile(r"\.exec\s*\(",                                   re.I), "api:exec_call",          2),
    (re.compile(r"ProcessBuilder",                                  re.I), "api:processbuilder",   3),
    # Class loading / code injection
    (re.compile(r"defineClass\s*\(",                                re.I), "api:defineClass",      3),
    (re.compile(r"URLClassLoader",                                  re.I), "api:url_classloader",  2),
    (re.compile(r"javax\.tools\.JavaCompiler",                      re.I), "api:in_memory_compile",3),
    (re.compile(r"groovy\.lang\.GroovyClassLoader|GroovyShell",     re.I), "api:groovy_exec",      2),
    # Reflection abuse
    (re.compile(r"setAccessible\s*\(\s*true",                       re.I), "api:reflection_bypass",1),
    (re.compile(r"\.invoke\s*\(",                                   re.I), "api:reflect_invoke",   1),
    # Scripting / expression engines (OGNL eval = arbitrary code exec)
    (re.compile(r"ScriptEngine|ScriptEngineManager",                re.I), "api:script_engine",    2),
    (re.compile(r"ognl\.Ognl|OgnlContext|Ognl\.getValue",           re.I), "api:ognl_exec",        3),
    (re.compile(r"ELProcessor|ExpressionFactory|ELContext",         re.I), "api:el_exec",          2),
    # File write (backdoor dropper / file manager shells)
    (re.compile(r"FileOutputStream|FileWriter|RandomAccessFile|new\s+PrintWriter\s*\(", re.I), "api:file_write", 2),
    (re.compile(r"new\s+String\s*\(\s*new\s+char\s*\[",              re.I), "api:char_array_obf",   1),
    (re.compile(r"getBytes\(\)|getBytes\s*\(['\"]",                 re.I), "api:bytes_write",      1),
    # Network / reverse shell
    (re.compile(r"Socket\s*\(|ServerSocket\s*\(",                   re.I), "api:socket",           2),
    # Misc dangerous
    (re.compile(r"sun\.misc\.Unsafe",                               re.I), "api:unsafe_api",       2),
    # Known tool fingerprints
    (re.compile(
        r"godzilla|behinder|icescorpion|regeorg|antsword|memshell|"
        r"JspDo|jspspy|jsp_kit|webacoo|b374k|laudanum",
        re.I,
    ), "tool:fingerprint", 4),
]


def _jsp_source_scan(jsp_path: Path) -> dict:
    """
    Rule-based scan of raw JSP source — fallback when Jasper cannot compile.
    Also normalises Unicode/octal escapes before scanning so obfuscated shells
    are not invisible to pattern matching.
    Extracts non-standard imports so analysts know which app classes to follow up.
    """
    try:
        raw = jsp_path.read_text(errors="replace")
    except Exception:
        return {"verdict": "ERROR", "tier": "ERROR", "ml_score": None,
                "rule": {"triggered": False, "rules": [], "risk": "LOW"},
                "detection_path": "jsp_source", "reason": "unreadable"}

    # Normalise escapes before pattern matching
    src = _normalize_escapes(raw)

    rules: list[str] = []
    score = 0

    for pat, label, pts in _SRC_PATTERNS:
        if pat.search(src):
            rules.append(label)
            score += pts

    stem = jsp_path.stem.lower()
    for kw in _SUSPICIOUS_KEYWORDS:
        if kw in stem:
            rules.append(f"name:{kw}")
            score += 2
            break

    # Always extract non-standard imports — useful even for BENIGN verdicts
    app_imports = _extract_imports(raw)

    base = {
        "ml_score":      None,
        "detection_path": "jsp_source",
        "imports":        app_imports,
    }

    if not rules:
        return {**base,
                "verdict": "BENIGN", "tier": "BENIGN",
                "rule": {"triggered": False, "rules": [], "risk": "LOW", "score": 0}}

    risk = "HIGH" if score >= 6 else "MEDIUM"
    rule = {"triggered": True, "rules": rules, "risk": risk, "score": score}
    tier = "CONFIRMED" if risk == "HIGH" else "HIGH"
    return {**base, "verdict": "WEBSHELL", "tier": tier, "rule": rule}


_SCRIPTLET_CONTENT_RE = re.compile(r'<%(?!@)(=|!)?.*?%>', re.DOTALL)


# ---------------------------------------------------------------------------
# Shell description generator
# ---------------------------------------------------------------------------

def describe_shell(result: dict) -> str:
    """
    Return a one-line analyst-facing description of what the shell is and
    what it can do, based on detection path, rules, and dynamic hits.
    """
    rules      = set(result.get("rule", {}).get("rules", []))
    dpath      = result.get("detection_path", "")
    ml_score   = result.get("ml_score")
    tier       = result.get("tier", "")
    verdict    = result.get("verdict", "")

    if verdict == "BENIGN":
        return "No webshell indicators detected"
    if tier == "ERROR":
        return "Analysis error"

    # --- Shell category (fileless vs file-based vs source-only) ---
    has_iface = any(r.startswith("iface:") for r in rules)
    is_dynamic = "+dynamic" in dpath or dpath == "dynamic"
    is_source  = "jsp_source" in dpath and not is_dynamic

    # Determine injection type from interface labels
    iface_labels = [r[len("iface:"):] for r in rules if r.startswith("iface:")]
    if any(x in iface_labels for x in ("Filter",)):
        shell_type = "Filter memory shell (fileless)"
    elif any(x in iface_labels for x in ("Valve", "ValveBase")):
        shell_type = "Tomcat Valve memory shell (fileless)"
    elif any(x in iface_labels for x in ("HandlerInterceptor",)):
        shell_type = "Spring interceptor memory shell (fileless)"
    elif any(x in iface_labels for x in ("ClassFileTransformer",)):
        shell_type = "Java agent memory shell (fileless — instruments JVM bytecode)"
    elif any(x in iface_labels for x in ("Endpoint", "ServerEndpointConfig$Configurator",
                                          "WebSocketHandler", "ChannelHandler",
                                          "ChannelInboundHandler")):
        shell_type = "WebSocket/Netty memory shell (fileless)"
    elif any(x in iface_labels for x in ("HttpServlet", "Servlet",
                                          "ServletContextListener",
                                          "ServletRequestListener",
                                          "HttpSessionListener")):
        shell_type = "Servlet/listener memory shell (fileless)"
    elif is_source:
        shell_type = "JSP webshell (source-based detection)"
    elif ml_score is not None:
        shell_type = "File-based webshell (bytecode anomaly)"
    else:
        shell_type = "Webshell (unclassified)"

    # --- Capabilities ---
    caps: list[str] = []

    exec_rules = {"api:runtime_exec", "api:exec_call", "api:processbuilder",
                  "dynamic:api:runtime_exec", "dynamic:api:processbuilder"}
    if rules & exec_rules:
        verb = "CONFIRMED OS command execution" if is_dynamic and rules & {
            "dynamic:api:runtime_exec", "dynamic:api:processbuilder"} \
            else "OS command execution"
        caps.append(verb)

    if "api:defineClass" in rules or "dynamic:api:defineClass" in rules:
        verb = "CONFIRMED bytecode injection" if "dynamic:api:defineClass" in rules \
            else "bytecode injection (loads class at runtime)"
        caps.append(verb)

    if "api:url_classloader" in rules:
        caps.append("remote class loading (URLClassLoader)")

    if "api:in_memory_compile" in rules:
        caps.append("in-memory Java compilation (JavaCompiler)")

    if "api:groovy_exec" in rules:
        caps.append("Groovy script execution (arbitrary code)")

    if "api:script_engine" in rules:
        caps.append("ScriptEngine execution (JS/Groovy eval)")

    if "api:ognl_exec" in rules:
        caps.append("OGNL expression evaluation (Struts2-style RCE)")

    if "api:el_exec" in rules:
        caps.append("EL expression evaluation (Spring/JSF RCE)")

    write_rules = {"api:file_write", "api:bytes_write", "dynamic:api:file_write"}
    if rules & write_rules:
        verb = "CONFIRMED file write" if "dynamic:api:file_write" in rules \
            else "arbitrary file write (dropper/file manager)"
        caps.append(verb)

    if "api:socket" in rules or "dynamic:api:socket" in rules:
        verb = "CONFIRMED network socket" if "dynamic:api:socket" in rules \
            else "network socket (reverse shell / C2)"
        caps.append(verb)

    if "api:reflection_bypass" in rules or "api:reflect_invoke" in rules:
        caps.append("reflection abuse (bypasses access control)")

    if "api:unsafe_api" in rules:
        caps.append("sun.misc.Unsafe (low-level JVM manipulation)")

    if "tool:fingerprint" in rules:
        # Try to get the specific tool name from the rule string
        tool_rules = [r for r in result.get("rule", {}).get("rules", [])
                      if r.startswith("tool:")]
        tool_name = tool_rules[0].replace("tool:", "") if tool_rules else "known tool"
        caps.append(f"matches known webshell signature ({tool_name})")

    if "api:char_array_obf" in rules:
        caps.append("char-array string obfuscation (evasion)")

    if "import:app_class_dependency" in rules:
        imps = result.get("imports", [])
        imp_str = ", ".join(imps[:3]) if imps else "unknown"
        caps.append(f"shell logic in app dependency ({imp_str})")

    # Name-based
    name_rules = [r[len("name:"):] for r in rules if r.startswith("name:")]
    if name_rules:
        caps.append(f"suspicious filename keyword ({', '.join(name_rules)})")

    # --- Assemble ---
    if caps:
        return f"{shell_type} — {'; '.join(caps)}"
    elif ml_score is not None:
        return f"{shell_type} — ML anomaly score {ml_score:.4f}"
    else:
        return shell_type


# Dynamic hits that guarantee CONFIRMED (we literally watched it execute)
_DYNAMIC_CONFIRM = {"api:runtime_exec", "api:processbuilder", "api:defineClass"}
# Dynamic scores for rule recalculation
_DYNAMIC_SCORES  = {"api:runtime_exec": 3, "api:processbuilder": 3,
                    "api:defineClass": 3, "api:file_write": 2, "api:socket": 2}


def _apply_dynamic_hits(result: dict, dynamic_hits: list[str]) -> dict:
    """Merge Java-agent dynamic hits into a result dict, upgrading tier if warranted."""
    if not dynamic_hits:
        return result

    rule = result.setdefault("rule", {"triggered": False, "rules": [], "risk": "LOW", "score": 0})
    existing = set(rule.get("rules", []))
    new_hits  = [h for h in dynamic_hits if h not in existing]

    if not new_hits:
        return result

    rule["rules"]     = rule.get("rules", []) + [f"dynamic:{h}" for h in new_hits]
    rule["triggered"] = True
    extra_score       = sum(_DYNAMIC_SCORES.get(h, 1) for h in new_hits)
    rule["score"]     = rule.get("score", 0) + extra_score
    rule["risk"]      = "HIGH" if rule["score"] >= 3 else "MEDIUM"

    dpath = result.get("detection_path", "")
    result["detection_path"] = dpath + ("+dynamic" if dpath else "dynamic")

    # Verdict upgrade: confirmed exec/injection = CONFIRMED; anything else = at least HIGH
    if any(h in _DYNAMIC_CONFIRM for h in new_hits):
        result["verdict"] = "WEBSHELL"
        result["tier"]    = "CONFIRMED"
    elif result.get("tier") in ("BENIGN", "MEDIUM", "HIGH"):
        result["verdict"] = "WEBSHELL"
        result["tier"]    = "HIGH" if result.get("tier") != "CONFIRMED" else "CONFIRMED"

    return result


def _compile_and_pick_worst(jsp_path: Path, predictor: "Predictor") -> tuple[dict, list[Path]]:
    """
    Compile a JSP via Docker Tomcat, run ML+rule detector on the javap output,
    and merge any Java-agent dynamic hits.  Falls back to source scan on failure.

    Option B heuristic: if compilation fails AND the JSP has non-standard
    imports AND has Java scriptlet blocks, escalate to MEDIUM.
    """
    compile_jsp = _load_jsp_compiler()

    try:
        javap_text, dynamic_hits = compile_jsp(jsp_path)
    except RuntimeError:
        src_result = _jsp_source_scan(jsp_path)

        # Escalate: non-standard imports + scriptlet code = unresolvable dependency shell
        if src_result.get("tier") == "BENIGN" and src_result.get("imports"):
            try:
                raw = jsp_path.read_text(errors="replace")
            except Exception:
                raw = ""
            if _SCRIPTLET_CONTENT_RE.search(raw):
                src_result = {
                    **src_result,
                    "verdict": "WEBSHELL",
                    "tier": "MEDIUM",
                    "rule": {
                        "triggered": True,
                        "rules": ["import:app_class_dependency"],
                        "risk": "MEDIUM",
                        "score": 2,
                    },
                }

        src_result["description"] = describe_shell(src_result)
        return src_result, []

    result = predictor.predict_from_javap(jsp_path, javap_text)
    result = _apply_dynamic_hits(result, dynamic_hits)
    result["description"] = describe_shell(result)
    return result, []


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cli_mode(input_file: str):
    path = Path(input_file)
    if not path.exists():
        print(f"File not found: {path}"); sys.exit(1)

    is_jsp = path.suffix.lower() == ".jsp"
    if not is_jsp and path.suffix.lower() != ".class":
        print(f"Only .class or .jsp files are supported (got: {path.suffix})")
        sys.exit(1)

    predictor = Predictor()
    temp_files: list[Path] = []

    try:
        if is_jsp:
            print(f"\n  Compiling JSP via Docker Tomcat ...")
            result, temp_files = _compile_and_pick_worst(path, predictor)
        else:
            result = predictor.predict(path)
    except RuntimeError as e:
        print(f"\n  [ERROR] {e}")
        sys.exit(1)
    finally:
        for f in temp_files:
            f.unlink(missing_ok=True)

    colours = {"CONFIRMED":"\033[91m","HIGH":"\033[91m","MEDIUM":"\033[93m",
               "BENIGN":"\033[92m","ERROR":"\033[90m"}
    c = colours.get(result["tier"], ""); rst = "\033[0m"

    dpath    = result.get("detection_path", "unknown")
    if dpath == "jsp_source":
        priority = "source-scan (compile failed)"
    elif dpath == "fileless":
        priority = "rules-first"
    else:
        priority = "ML-first"

    print(f"\n  File    : {path.name}{' (compiled from JSP)' if is_jsp else ''}")
    print(f"  Verdict : {c}{result['verdict']} [{result['tier']}]{rst}")
    print(f"  Summary : {result.get('description', '')}")
    print(f"  Path    : {dpath} ({priority})")
    print(f"  ML score: {result['ml_score']}")
    rule = result["rule"]
    if rule["triggered"]:
        print(f"  Rules   : [{rule['risk']}] {'; '.join(rule['rules'])}")
    else:
        print(f"  Rules   : none triggered")
    imports = result.get("imports")
    if imports:
        print(f"  Imports : {', '.join(imports)}")

# ---------------------------------------------------------------------------
# FastAPI server
# ---------------------------------------------------------------------------

def run_server():
    try:
        from fastapi import FastAPI, File, HTTPException, UploadFile
        from fastapi.responses import JSONResponse
        import uvicorn
    except ImportError:
        print("Missing deps: pip install fastapi uvicorn python-multipart"); sys.exit(1)

    predictor = Predictor()
    app = FastAPI(title="ShellBreaker", version="2.2",
                  description="Hybrid Java memory webshell detector (ResNet50/XGBoost + rules).")

    @app.post("/predict")
    async def predict(file: UploadFile = File(...)):
        name   = file.filename or ""
        suffix = Path(name).suffix.lower()
        if suffix not in (".class", ".jsp"):
            raise HTTPException(400, "Only .class or .jsp files accepted")

        data = await file.read()
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)
            if suffix == ".jsp":
                # Give it the original filename so Tomcat produces a sensible class name.
                named_tmp = tmp_path.parent / name
                tmp_path.rename(named_tmp)
                tmp_path = named_tmp

        temp_files = [tmp_path]
        try:
            if suffix == ".jsp":
                result, compiled = _compile_and_pick_worst(tmp_path, predictor)
                temp_files.extend(compiled)
            else:
                result = predictor.predict(tmp_path)
        except RuntimeError as e:
            raise HTTPException(500, str(e))
        finally:
            for f in temp_files:
                f.unlink(missing_ok=True)

        with open(LOG_PATH, "a") as f:
            f.write(json.dumps({"ts": int(time.time()), "file": name, **result}) + "\n")
        return JSONResponse(content=result)

    @app.get("/threshold")
    def get_threshold():
        return {
            "inference_threshold": predictor.inf_threshold,
            "high_threshold":      HIGH_THRESHOLD,
            "paths": {
                "fileless (injection interface detected — rules-first)": {
                    "CONFIRMED": "rule HIGH",
                    "HIGH":      "rule MEDIUM",
                    "MEDIUM":    f"ML >= {predictor.inf_threshold:.4f}",
                    "BENIGN":    "neither",
                },
                "file_based (no injection interface — ML-first)": {
                    "CONFIRMED": f"ML >= {HIGH_THRESHOLD}",
                    "HIGH":      f"ML >= {predictor.inf_threshold:.4f}",
                    "MEDIUM":    "rule HIGH or MEDIUM",
                    "BENIGN":    "neither",
                },
            },
        }

    print("\nStarting ShellBreaker API  http://localhost:8080")
    print("  POST /predict   -- submit .class or .jsp file")
    print("  GET  /threshold -- view tiers")
    print("  GET  /docs      -- Swagger UI")
    print("  Note: .jsp analysis requires Docker (docker compose up -d)\n")
    uvicorn.run(app, host="0.0.0.0", port=8080)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli_mode(sys.argv[1])   # accepts .class or .jsp
    else:
        run_server()
