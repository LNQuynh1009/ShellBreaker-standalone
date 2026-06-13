package com.shellbreaker;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.JarFile;

public class Agent {

    // Inlined — do not reference ShellTransformer after the bootstrap-CL append.
    private static final Set<String> RETRANSFORM_TARGETS = new HashSet<>(Arrays.asList(
            "java.lang.Runtime",
            "java.lang.ProcessBuilder",
            "java.lang.ClassLoader",
            "java.io.FileOutputStream",
            "java.io.FileWriter",
            "java.io.PrintWriter",
            "java.net.Socket",
            "java.net.ServerSocket"
    ));

    public static void premain(String args, Instrumentation inst) throws Exception {
        init(args, inst);
    }

    public static void agentmain(String args, Instrumentation inst) throws Exception {
        init(args, inst);
    }

    private static void init(String args, Instrumentation inst) throws Exception {
        String logPath = (args != null && !args.trim().isEmpty())
                ? args.trim() : "/tmp/sb_agent.log";

        // Register the transformer FIRST while all ASM classes are in the app CL only.
        inst.addTransformer(new ShellTransformer(logPath), true);

        // Add ONLY the logger JAR (no ASM) to the bootstrap CL so that
        // Logger.log() is reachable when bootstrap-loaded classes call it.
        // The main agent JAR (with ASM) stays in the app CL — this prevents
        // the ASM cross-CL IllegalAccessError.
        try {
            URL agentLoc = Agent.class.getProtectionDomain().getCodeSource().getLocation();
            File agentDir = new File(agentLoc.toURI()).getParentFile();
            File loggerJar = new File(agentDir, "shellbreaker-logger.jar");
            if (loggerJar.exists()) {
                inst.appendToBootstrapClassLoaderSearch(new JarFile(loggerJar));
                System.out.println("[ShellBreaker-Agent] Logger JAR added to bootstrap CL.");
            } else {
                System.err.println("[ShellBreaker-Agent] shellbreaker-logger.jar not found at "
                        + loggerJar + " — dynamic hits will not be captured.");
            }
        } catch (Exception e) {
            System.err.println("[ShellBreaker-Agent] Bootstrap CL setup failed: " + e.getMessage());
        }

        // Retransform target classes already loaded before the agent attached.
        int retransformed = 0;
        for (Class<?> c : inst.getAllLoadedClasses()) {
            if (RETRANSFORM_TARGETS.contains(c.getName())) {
                try {
                    inst.retransformClasses(c);
                    retransformed++;
                } catch (Exception ignored) {}
            }
        }

        System.out.println("[ShellBreaker-Agent] Loaded. Log=" + logPath
                + "  retransformed=" + retransformed + " classes.");
    }
}
