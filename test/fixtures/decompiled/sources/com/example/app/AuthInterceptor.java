package com.example.app;

public class AuthInterceptor implements Interceptor {
    private static final String USER_AGENT_FORMAT = "ExampleApp/%s (Android %s; %s)";

    public Response intercept(Chain chain) {
        Request request = chain.request().newBuilder()
            .header("X-App-Version", "3.2.1")
            .header("X-Platform", "android")
            .header("Authorization", authToken)
            .build();
        return chain.proceed(request);
    }
}
