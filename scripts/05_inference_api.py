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

def disassemble(class_path: Path) -> tuple[list[str] | None, str]:
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
        return (ops if ops else None), r.stdout
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

    def predict(self, class_path: Path) -> dict:
        ops, javap_text = disassemble(class_path)

        if ops is None:
            return {
                "verdict": "ERROR", "tier": "ERROR",
                "ml_score": None,
                "rule": {"triggered": False, "rules": [], "risk": "LOW"},
                "reason": "javap failed",
            }

        if len(ops) < 4:
            # Interface / annotation / empty abstract class — no executable bytecode.
            # ML cannot run (no opcode matrix), but the constant pool is still
            # readable so the rule engine can catch tool strings or dangerous refs.
            rule = rule_check(class_path, javap_text)
            if rule["triggered"]:
                verdict, tier, dpath = combined_verdict(0.0, rule, self.inf_threshold)
                return {
                    "verdict": verdict, "tier": tier,
                    "detection_path": dpath,
                    "ml_score": None, "rule": rule,
                    "backend": self.backend,
                }
            return {
                "verdict": "BENIGN", "tier": "BENIGN",
                "detection_path": "interface",
                "ml_score": None, "rule": rule,
                "backend": self.backend,
            }

        ml_score               = self._ml_score(class_path, ops, javap_text)
        rule                   = rule_check(class_path, javap_text)
        verdict, tier, path    = combined_verdict(ml_score, rule, self.inf_threshold)

        return {
            "verdict":        verdict,
            "tier":           tier,
            "detection_path": path,
            "ml_score":       round(ml_score, 4),
            "rule":           rule,
            "backend":        self.backend,
        }

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cli_mode(class_file: str):
    path = Path(class_file)
    if not path.exists():
        print(f"File not found: {path}"); sys.exit(1)

    predictor = Predictor()
    result    = predictor.predict(path)

    colours = {"CONFIRMED":"\033[91m","HIGH":"\033[91m","MEDIUM":"\033[93m",
               "BENIGN":"\033[92m","ERROR":"\033[90m"}
    c = colours.get(result["tier"], ""); rst = "\033[0m"

    dpath     = result.get("detection_path", "unknown")
    priority  = "rules-first" if dpath == "fileless" else "ML-first"

    print(f"\n  File    : {path.name}")
    print(f"  Verdict : {c}{result['verdict']} [{result['tier']}]{rst}")
    print(f"  Path    : {dpath} ({priority})")
    print(f"  ML score: {result['ml_score']}")
    rule = result["rule"]
    if rule["triggered"]:
        print(f"  Rules   : [{rule['risk']}] {'; '.join(rule['rules'])}")
    else:
        print(f"  Rules   : none triggered")

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
        if not file.filename.endswith(".class"):
            raise HTTPException(400, "Only .class files accepted")
        data = await file.read()
        with tempfile.NamedTemporaryFile(suffix=".class", delete=False) as tmp:
            tmp.write(data); tmp_path = Path(tmp.name)
        try:
            result = predictor.predict(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps({"ts": int(time.time()), "file": file.filename, **result}) + "\n")
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
    print("  POST /predict   — submit .class file")
    print("  GET  /threshold — view tiers")
    print("  GET  /docs      — Swagger UI\n")
    uvicorn.run(app, host="0.0.0.0", port=8080)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli_mode(sys.argv[1])
    else:
        run_server()
