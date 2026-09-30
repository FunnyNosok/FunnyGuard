package com.protectedclient.nativecore;

public final class NativeDemo {

    public static void main(String[] args) {
        String dll = args.length > 0 ? args[0] : "build\\nativecore.dll";
        NativeCore.load(dll);

        System.out.println("[demo] antiDebug: " + NativeCore.antiDebug());

        long x = 42L;
        System.out.println("[demo] secretTransform(" + x + "): " + NativeCore.secretTransform(x));

        String token = NativeCore.issueLicense("player123");
        System.out.println("[demo] issued license token: " + token);

        String good = NativeCore.verifyLicense(token);
        System.out.println("[demo] verify(valid token) -> subject: " + good);

        String bad = NativeCore.verifyLicense("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        System.out.println("[demo] verify(garbage token) -> subject: " + bad);
    }
}
