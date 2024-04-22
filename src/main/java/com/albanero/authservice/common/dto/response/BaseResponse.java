package com.albanero.authservice.common.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;

import jakarta.annotation.Nullable;

/**
 * Base Response DTO class for all REST API Calls
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Data

public class BaseResponse {


    String message;

    Boolean success;

    Object payload;

    @Nullable
    String statusCode;
}
