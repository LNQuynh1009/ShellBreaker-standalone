package com.shellbreaker;

import org.objectweb.asm.*;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import java.util.*;

public class ShellTransformer implements ClassFileTransformer {

    // internal/class/name -> set of method names to intercept
    static final Map<String, Set<String>> TARGETS = new HashMap<>();
    // internal/class/name -> label written to log
    static final Map<String, String> LABELS = new HashMap<>();

    static {
        put("java/lang/Runtime",        "exec",       "api:runtime_exec");
        put("java/lang/ProcessBuilder", "start",      "api:processbuilder");
        put("java/lang/ClassLoader",    "defineClass","api:defineClass");
        put("java/io/FileOutputStream", "<init>",     "api:file_write");
        put("java/io/FileWriter",       "<init>",     "api:file_write");
        put("java/io/PrintWriter",      "<init>",     "api:file_write");
        put("java/net/Socket",          "<init>",     "api:socket");
        put("java/net/ServerSocket",    "<init>",     "api:socket");
    }

    private static void put(String cls, String method, String label) {
        TARGETS.computeIfAbsent(cls, k -> new HashSet<>()).add(method);
        LABELS.put(cls, label);
    }

    static boolean isTarget(String dotName) {
        return TARGETS.containsKey(dotName.replace('.', '/'));
    }

    private final String logPath;

    public ShellTransformer(String logPath) { this.logPath = logPath; }

    @Override
    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain domain, byte[] buf) {
        if (className == null || !TARGETS.containsKey(className)) return null;
        try {
            ClassReader cr = new ClassReader(buf);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS) {
                @Override
                protected String getCommonSuperClass(String t1, String t2) {
                    return "java/lang/Object";
                }
            };
            cr.accept(new TargetClassVisitor(cw, className, logPath), 0);
            return cw.toByteArray();
        } catch (Throwable t) {
            return null; // never break class loading
        }
    }
}

class TargetClassVisitor extends ClassVisitor {
    private final String className;
    private final String logPath;

    TargetClassVisitor(ClassVisitor cv, String className, String logPath) {
        super(Opcodes.ASM9, cv);
        this.className = className;
        this.logPath = logPath;
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String desc,
                                     String sig, String[] ex) {
        MethodVisitor mv = super.visitMethod(access, name, desc, sig, ex);
        Set<String> methods = ShellTransformer.TARGETS.get(className);
        if (methods != null && methods.contains(name)) {
            String label = ShellTransformer.LABELS.getOrDefault(className, "api:unknown");
            return new LoggingMethodVisitor(mv, label, logPath);
        }
        return mv;
    }
}

class LoggingMethodVisitor extends MethodVisitor {
    private final String label;
    private final String logPath;

    LoggingMethodVisitor(MethodVisitor mv, String label, String logPath) {
        super(Opcodes.ASM9, mv);
        this.label = label;
        this.logPath = logPath;
    }

    @Override
    public void visitCode() {
        super.visitCode();
        // Inject: Logger.log(label, logPath)  — static call, safe before super() in constructors
        mv.visitLdcInsn(label);
        mv.visitLdcInsn(logPath);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                "com/shellbreaker/Logger", "log",
                "(Ljava/lang/String;Ljava/lang/String;)V", false);
    }
}
