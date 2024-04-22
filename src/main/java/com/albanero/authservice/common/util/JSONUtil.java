package com.albanero.authservice.common.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import com.albanero.authservice.exception.JSONUtilException;

import static com.albanero.authservice.common.constants.LoggerConstants.AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG;
public class JSONUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(JSONUtil.class);
    private static final String JSON_UTIL = "JSONUtil";

    /**
     * Method to serialize Object to JSON string
     *
     * @param obj {@link Object}
     * @return {@link String}
     */
    public static String serialize(Object obj) {
        try {
            ObjectWriter ow = new ObjectMapper().writer();
            return ow.writeValueAsString(obj);
        } catch (JsonProcessingException jpe) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, JSON_UTIL, "serialize", jpe.getOriginalMessage(), jpe.getStackTrace());
            throw new JSONUtilException("Action Failed! in JSONUtil::serialize", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Method to convert a JSON string to Object
     *
     * @param mappingClass {@link Class<T>}
     * @param json         {@link String}
     * @return {@link T}
     */
    public static <T> T deserialize(Class<T> mappingClass, String json) {
        try {
            return new ObjectMapper().readerFor(mappingClass).readValue(json);
        } catch (JsonProcessingException jpe) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, JSON_UTIL, "deserialize", jpe.getOriginalMessage(), jpe.getStackTrace());
            throw new JSONUtilException("Action Failed! in JSONUtil::deserialize", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Method to cast Object having same properties
     *
     * @param mappingClass {@link Class<T>}
     * @param obj          {@link Object}
     * @return {@link <T> }
     */
    public static <T> T castObject(Class<T> mappingClass, Object obj) {
        return deserialize(mappingClass, serialize(obj));
    }

    private JSONUtil() {
        throw new IllegalStateException("JSONUtil Utility class");
    }
}
