#!/usr/bin/env python3
"""
compile_jsp_local.py — Compile .jsp to .class by extracting Java scriptlets
and wrapping them in a minimal HttpServlet stub compiled with javac.

No Docker or Tomcat needed — only javac (JDK) and a servlet-api JAR.

Why this works for detection:
  The malicious payload in a JSP always lives in scriptlet blocks
  (<% %>, <%! %>, <%= %>).  Extracting these and compiling them into a
  plain HttpServlet gives the ML model clean user-authored bytecode without
  Jasper boilerplate.  Imports or JSP-include tags that merely reference
  another file do NOT appear in the compiled bytecode, which avoids false
  positives on JSPs that call external classes.

Two-pass strategy:
  Pass 1 — compile the full scriptlet extraction as-is.
  Pass 2 — if that fails (e.g. missing imported classes), keep only lines
            containing known dangerous API names and retry.  Malicious code
            that uses exec/defineClass/reflection survives; benign code that
            fails because of missing app-specific imports is dropped.

Public API
----------
  compile_jsp_local(jsp_path: Path) -> Path | None
      Returns a temp Path to the compiled .class file, or None if the JSP
      has no scriptlet content or both passes fail.
      The CALLER must delete the returned Path when done.
"""

import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Servlet-API JAR — downloaded once to libs/ on first use
# ---------------------------------------------------------------------------

_LIBS_DIR    = Path(__file__).parent.parent / "libs"
_JAKARTA_JAR = _LIBS_DIR / "jakarta.servlet-api-5.0.0.jar"
_JAVAX_JAR   = _LIBS_DIR / "javax.servlet-api-4.0.1.jar"
_JAKARTA_URL = (
    "https://repo1.maven.org/maven2/jakarta/servlet/"
    "jakarta.servlet-api/5.0.0/jakarta.servlet-api-5.0.0.jar"
)
_JAVAX_URL = (
    "https://repo1.maven.org/maven2/javax/servlet/"
    "javax.servlet-api/4.0.1/javax.servlet-api-4.0.1.jar"
)


def _ensure_servlet_jar() -> tuple[Path, bool]:
    """Return (jar_path, is_jakarta). Downloads on first use."""
    _LIBS_DIR.mkdir(parents=True, exist_ok=True)
    if _JAKARTA_JAR.exists():
        return _JAKARTA_JAR, True
    if _JAVAX_JAR.exists():
        return _JAVAX_JAR, False
    print("  [compile_jsp_local] Downloading servlet-api JAR (one-time setup)...",
          end="", flush=True)
    for url, dest, is_jakarta in [
        (_JAKARTA_URL, _JAKARTA_JAR, True),
        (_JAVAX_URL,   _JAVAX_JAR,   False),
    ]:
        try:
            urllib.request.urlretrieve(url, dest)
            print(f" done ({dest.stat().st_size // 1024} KB)")
            return dest, is_jakarta
        except Exception:
            dest.unlink(missing_ok=True)
    print(" FAILED", file=sys.stderr)
    raise RuntimeError(
        "Cannot download servlet-api.jar — check your internet connection."
    )


# ---------------------------------------------------------------------------
# JSP parsing
# ---------------------------------------------------------------------------

# <%@ page import="a.b.C, d.e.F" %> — may appear multiple times
_PAGE_IMPORT_RE = re.compile(
    r'<%@\s*page\b[^%]*?\bimport\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE | re.DOTALL,
)
# JSP comments <%-- ... --%> must be stripped before other patterns
_JSP_COMMENT_RE = re.compile(r'<%--.*?--%>', re.DOTALL)
# <%! declarations %>  <%  scriptlets %>  <%= expressions %>
# Process in document order; expressions first so <%= is not matched as <% + =
_JSP_TOKEN_RE = re.compile(r'<%=(.*?)%>|<%!(.*?)%>|<%(?![@!=-])(.*?)%>', re.DOTALL)

# Unicode and octal escape normalisation (obfuscation bypass)
_UNICODE_ESC = re.compile(r'\\u([0-9a-fA-F]{4})')
_OCTAL_ESC   = re.compile(r'\\([0-7]{1,3})')


def _normalize(src: str) -> str:
    src = _UNICODE_ESC.sub(lambda m: chr(int(m.group(1), 16)), src)
    src = _OCTAL_ESC.sub(
        lambda m: chr(int(m.group(1), 8)) if int(m.group(1), 8) < 128 else m.group(0),
        src,
    )
    return src


def _parse_jsp(source: str) -> tuple[list[str], str, str]:
    """
    Returns (import_lines, declarations_block, service_body_block).

    import_lines      — Java import statements from <%@ page import="..." %>
    declarations_block — content of <%! ... %> tags (class-body level)
    service_body_block — content of <% ... %> and <%= ... %> tags (method level)
    """
    source = _normalize(source)
    source = _JSP_COMMENT_RE.sub("", source)   # strip JSP comments before tokenising

    imports: list[str] = []
    for m in _PAGE_IMPORT_RE.finditer(source):
        for cls in m.group(1).split(","):
            cls = cls.strip().rstrip(".*")
            if cls:
                imports.append(f"import {cls};")

    decls: list[str] = []
    body:  list[str] = []

    for m in _JSP_TOKEN_RE.finditer(source):
        expr, decl, script = m.group(1), m.group(2), m.group(3)
        if expr is not None:
            # <%= expr %> → out.print(expr);
            body.append(f"out.print({expr.strip()});")
        elif decl is not None:
            decls.append(decl)
        elif script is not None:
            body.append(script)

    return imports, "\n".join(decls), "\n".join(body)


# ---------------------------------------------------------------------------
# Java source templates
# ---------------------------------------------------------------------------

_TEMPLATE_JAKARTA = """\
package __sb__;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.*;
{IMPORTS}
public class JspExtract extends HttpServlet {{
{DECLS}
    @Override
    public void service(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, java.io.IOException {{
        PrintWriter out = response.getWriter();
        HttpSession session = request.getSession();
        Object page = this;
        jakarta.servlet.ServletContext application = getServletContext();
        jakarta.servlet.ServletConfig config = getServletConfig();
{BODY}
    }}
}}
"""

_TEMPLATE_JAVAX = """\
package __sb__;
import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
{IMPORTS}
public class JspExtract extends HttpServlet {{
{DECLS}
    @Override
    public void service(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, java.io.IOException {{
        PrintWriter out = response.getWriter();
        HttpSession session = request.getSession();
        Object page = this;
        javax.servlet.ServletContext application = getServletContext();
        javax.servlet.ServletConfig config = getServletConfig();
{BODY}
    }}
}}
"""

# Lines containing any of these strings are kept in the Pass-2 fallback
_DANGER_KEYWORDS = (
    "Runtime", "exec", "ProcessBuilder", "defineClass", "ClassLoader",
    "ScriptEngine", "setAccessible", "Unsafe", "getRuntime",
    "invoke", "reflect", "Proxy", "URLClassLoader", "JavaCompiler",
    "GroovyClassLoader", "GroovyShell",
)


# ---------------------------------------------------------------------------
# Compilation helper
# ---------------------------------------------------------------------------

def _try_compile(java_src: str, servlet_jar: Path,
                 extra_flags: list[str] | None = None) -> Path | None:
    """
    Write java_src to a temp dir, compile, copy the resulting .class to a
    standalone temp file, and return its path.  Returns None on failure.
    """
    with tempfile.TemporaryDirectory() as tmp:
        pkg = Path(tmp) / "__sb__"
        pkg.mkdir()
        java_file = pkg / "JspExtract.java"
        java_file.write_text(java_src, encoding="utf-8", errors="replace")

        cmd = ["javac", "-encoding", "UTF-8", "-nowarn", "-proc:none",
               "-cp", str(servlet_jar)]
        if extra_flags:
            cmd.extend(extra_flags)
        cmd.append(str(java_file))

        r = subprocess.run(cmd, capture_output=True, timeout=20)
        if r.returncode != 0:
            return None

        class_file = pkg / "JspExtract.class"
        if not class_file.exists():
            return None

        # Copy out before TemporaryDirectory is deleted
        import os
        fd, out_path = tempfile.mkstemp(suffix=".class", prefix="sb_jsp_")
        os.close(fd)
        shutil.copy2(class_file, out_path)
        return Path(out_path)


# ---------------------------------------------------------------------------
# Compat rewrites — replace removed JDK APIs so code compiles on JDK 11+
# ---------------------------------------------------------------------------

def _compat_body(body: str) -> str:
    body = re.sub(r'new\s+BASE64Decoder\(\)\.decodeBuffer\(',
                  'java.util.Base64.getDecoder().decode(', body)
    body = re.sub(r'new\s+sun\.misc\.BASE64Decoder\(\)\.decodeBuffer\(',
                  'java.util.Base64.getDecoder().decode(', body)
    body = re.sub(r'new\s+BASE64Encoder\(\)\.encode\(',
                  'java.util.Base64.getEncoder().encodeToString(', body)
    body = re.sub(r'new\s+sun\.misc\.BASE64Encoder\(\)\.encode\(',
                  'java.util.Base64.getEncoder().encodeToString(', body)
    return body


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compile_jsp_local(jsp_path: Path) -> Path | None:
    """
    Extract Java scriptlets from jsp_path, compile to .class, return path.

    Returns None if the JSP has no scriptlet content or both compile passes fail.
    The caller must delete the returned Path when done (use try/finally).
    """
    source = jsp_path.read_text(encoding="utf-8", errors="replace")
    imports, decls, body = _parse_jsp(source)

    if not body.strip() and not decls.strip():
        return None  # pure template JSP — nothing to compile

    servlet_jar, is_jakarta = _ensure_servlet_jar()
    template = _TEMPLATE_JAKARTA if is_jakarta else _TEMPLATE_JAVAX

    # Pass 1: full extraction
    java_src = template.format(
        IMPORTS="\n".join(imports),
        DECLS=decls,
        BODY=body,
    )
    result = _try_compile(java_src, servlet_jar)
    if result:
        return result

    # Pass 2: replace removed sun.misc APIs with modern equivalents and retry
    java_src2 = template.format(
        IMPORTS="\n".join(i for i in imports
                          if "sun.misc.BASE64" not in i and "com.sun." not in i),
        DECLS=decls,
        BODY=_compat_body(body),
    )
    # jdk.unsupported exports sun.misc (Unsafe etc.); java.base does not
    sun_flags = ["--add-exports", "jdk.unsupported/sun.misc=ALL-UNNAMED"]
    result = _try_compile(java_src2, servlet_jar, extra_flags=sun_flags)
    if result:
        return result

    # Pass 3: strip all imports + keep only dangerous-API lines + sun.misc exposed
    minimal_body = "\n".join(
        line for line in _compat_body(body).splitlines()
        if any(kw in line for kw in _DANGER_KEYWORDS)
    )
    if not minimal_body.strip():
        return None

    java_src3 = template.format(IMPORTS="", DECLS="", BODY=minimal_body)
    return _try_compile(java_src3, servlet_jar, extra_flags=sun_flags)


# ---------------------------------------------------------------------------
# CLI (for testing)
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse, json, subprocess as sp
    ap = argparse.ArgumentParser(description="Compile a .jsp and print javap output.")
    ap.add_argument("jsp", help=".jsp file to compile")
    args = ap.parse_args()

    jsp_path = Path(args.jsp)
    if not jsp_path.exists():
        print(f"File not found: {jsp_path}", file=sys.stderr); sys.exit(1)

    class_path = compile_jsp_local(jsp_path)
    if class_path is None:
        print("No scriptlet content — nothing to compile."); sys.exit(0)

    try:
        r = sp.run(["javap", "-c", "-p", "-verbose", str(class_path)],
                   capture_output=True, text=True)
        print(r.stdout)
    finally:
        class_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
