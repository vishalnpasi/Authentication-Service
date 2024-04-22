package com.albanero.authservice.common.constants;


/**
 * Interface that provides RestController mapping constants for API endpoints
 */
public final class MappingConstants {

    public static final String APPLICATION_BASE = "/auth"; // application base mapping
    public static final String APPLICATION_USER_BASE = "/auth-user"; // application base mapping
    public static final String API_BASE = APPLICATION_BASE + "/api"; // api base mapping
    public static final String API_USER_BASE = APPLICATION_USER_BASE + "/api"; // api base mapping
    public static final String ACTUATOR = "/actuator/**"; // actuator mapping

    private MappingConstants() {
        throw new IllegalStateException("MappingConstants class");

    }

}



