package com.example.app;

public class ListingResponse {
    @SerializedName("id")
    private String id;

    @SerializedName("title")
    private String title;

    @SerializedName("price")
    private Integer price;

    @SerializedName("cursor")
    private String cursor;
}
