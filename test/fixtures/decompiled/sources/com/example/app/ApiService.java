package com.example.app;

public interface ApiService {
    @GET("/v1/listings")
    Single<ListingResponse> getListings();

    @POST("/v1/auth/login")
    Single<TokenResponse> login(@Body LoginRequest body);

    @GET("/v1/search")
    Single<SearchResponse> search(@Header("X-Api-Key") String apiKey, @Body SearchRequest filters);
}
