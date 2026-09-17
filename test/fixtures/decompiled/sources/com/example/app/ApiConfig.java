package com.example.app;

public class ApiConfig {
    public static final String apiBaseUrl = "https://api.example.com";
    public static final String webUrl = "https://www.example.com";
    public static final String supportUrl = "https://support.example.com";

    // noise that must be filtered out
    public static final String schemaNs = "https://schemas.android.com/apk/res/android";
    public static final String fonts = "https://fonts.gstatic.com/s/roboto/v30/font.woff2";
    public static final String firebaseDb = "https://example-app-default-rtdb.firebaseio.com";
    public static final String w3c = "http://www.w3.org/2000/svg";

    public String getApiBaseUrl() {
        return apiBaseUrl;
    }
}
