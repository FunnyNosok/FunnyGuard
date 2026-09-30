package com.protectedclient.example;

public final class Greeter {

    public String banner() {
        return "custom client build 1.0 running inside the protected class loader";
    }

    public int magicNumber() {
        return 1337 ^ 0x5A;
    }
}
