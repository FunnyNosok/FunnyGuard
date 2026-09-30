package com.protectedclient.example;

import jdk.internal.misc.PmchStrings;

public final class ClientMain {

    private static final String SECRET_ENDPOINT_TOKEN =
        "G2+se4evN/ZIrH5CEJtzbs0RrNxr5xn7FRmnfNFDmSELKUukUs9ugohX4BGL5M8KyPRsL+WSF+hBHuI/LyV6i9Z6";

    public static void main(String[] args) {
        System.out.println("[client] protected Minecraft client is starting");
        System.out.println("[client] loaded by classguard: "
            + ClientMain.class.getClassLoader().getClass().getName());

        Greeter greeter = new Greeter();
        System.out.println("[client] " + greeter.banner());
        System.out.println("[client] magic number: " + greeter.magicNumber());

        String endpoint = PmchStrings.reveal(SECRET_ENDPOINT_TOKEN);
        System.out.println("[client] decrypted protected string: " + endpoint);

        if (args.length > 0) {
            System.out.println("[client] received args: " + String.join(", ", args));
        }
        System.out.println("[client] client initialised successfully");
    }
}
