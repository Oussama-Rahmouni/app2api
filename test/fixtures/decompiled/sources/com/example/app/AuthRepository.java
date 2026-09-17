package com.example.app;

public class AuthRepository {
    private final String client_secret = "s3cr3t-value-here";
    private static final String client_id = "example-android-client";

    public void login(String user, String pass) {
        FormBody body = new FormBody.Builder()
            .add("client_id", "example-android-client")
            .add("client_secret", client_secret)
            .add("grant_type", "password")
            .add("username", user)
            .add("password", pass)
            .build();
    }

    public String tokenEndpoint() {
        String authenticationUrl = getApiBaseUrl() + "/oauth/token";
        return authenticationUrl;
    }

    private String getApiBaseUrl() {
        return "https://api.example.com";
    }
}
