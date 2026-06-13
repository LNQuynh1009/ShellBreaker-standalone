package com.shellbreaker;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;

public class Logger {

    // Prevents re-entry: Logger calling NIO would not recurse, but be safe.
    private static final ThreadLocal<Boolean> GUARD = ThreadLocal.withInitial(() -> false);

    public static void log(String label, String logPath) {
        if (GUARD.get()) return;
        GUARD.set(true);
        try {
            String caller = findJspCaller();
            if (caller == null) return; // not called from a JSP — ignore

            String line = System.currentTimeMillis() + "|" + label + "|" + caller + "\n";
            Files.write(Paths.get(logPath),
                    line.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Throwable t) {
            // Must never throw
        } finally {
            GUARD.set(false);
        }
    }

    private static String findJspCaller() {
        for (StackTraceElement e : Thread.currentThread().getStackTrace()) {
            // Jasper-compiled JSP classes live under org.apache.jsp.*
            if (e.getClassName().startsWith("org.apache.jsp.")) {
                return e.getClassName();
            }
        }
        return null;
    }
}
