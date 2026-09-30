package jdk.internal.misc;

import java.util.Optional;

public final class PmchGuard {

    private static final String[] DEBUG_MARKERS = {
        "-agentlib:jdwp",
        "-xrunjdwp",
        "-xdebug",
        "-javaagent",
        "-agentpath"
    };

    private PmchGuard() {
    }

    public static void enforce() {
        try {
            String policy = System.getenv("PMCH_GUARD");
            if (policy == null || policy.isEmpty()) {
                policy = "LOG";
            }
            if (policy.equalsIgnoreCase("OFF")) {
                return;
            }

            if (System.getProperty("jdk.attach.allowAttachSelf") == null) {
                System.setProperty("jdk.attach.allowAttachSelf", "false");
            }

            String detected = detect();
            System.err.println("[pmch-guard] runtime guard active (policy=" + policy + ")");

            if (detected != null) {
                System.err.println("[pmch-guard] debug/agent marker detected: " + detected);
                if (policy.equalsIgnoreCase("EXIT")) {
                    Runtime.getRuntime().halt(3);
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static String detect() {
        try {
            String[] arguments = VM.getRuntimeArguments();
            if (arguments != null) {
                for (String argument : arguments) {
                    if (argument == null) {
                        continue;
                    }
                    String lower = argument.toLowerCase();
                    for (String marker : DEBUG_MARKERS) {
                        if (lower.startsWith(marker)) {
                            return argument;
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        try {
            Optional<String> commandLine = ProcessHandle.current().info().commandLine();
            if (commandLine.isPresent()) {
                String lower = commandLine.get().toLowerCase();
                for (String marker : DEBUG_MARKERS) {
                    if (lower.contains(marker)) {
                        return marker;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }
}
