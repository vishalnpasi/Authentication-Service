package com.albanero.authservice.common.constants;



/**
 * Interface that provides RestController mapping constants
 * 
 */
public final class LoggerConstants {
	public static final  String   AUTHENTICATION_SERVICE_TAG =" Service : authentication-service, Class : {}, Operation : {} ";
	public static final String    AUTHENTICATION_SERVICE_START_LOG_TAG=  "Inside" +    AUTHENTICATION_SERVICE_TAG;
	public static final String    AUTHENTICATION_SERVICE_INFO_LOG_TAG=  "Inside" +    AUTHENTICATION_SERVICE_TAG + ", {} : {}";
	public static final String    AUTHENTICATION_SERVICE_END_LOG_TAG =  "Time taken by" +    AUTHENTICATION_SERVICE_TAG +   ", Elapsed Time : {}";

	public static final String    AUTHENTICATION_SERVICE_WARN_LOG_TAG=  "{}" + AUTHENTICATION_SERVICE_TAG + ", {} : {}";
	public static final String EXCEPTION_OCCURRED = "Exception occurred in ";
	public static final String    AUTHENTICATION_SERVICE_WARN_EXCEPTION_LOG_TAG = EXCEPTION_OCCURRED +  AUTHENTICATION_SERVICE_TAG  + ", errorMessage : {}, stackTrace : {}";

	public static final String    AUTHENTICATION_SERVICE_ERROR_LOG_TAG =  EXCEPTION_OCCURRED + AUTHENTICATION_SERVICE_TAG + ", errorMessage : {}, {} : {}";

	public static final String    AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO =  EXCEPTION_OCCURRED + AUTHENTICATION_SERVICE_TAG + ", errorMessage : {} {}, {} : {}";
	public static final String    AUTHENTICATION_SERVICE_LOG_TAG_WITH_MESSAGE =  EXCEPTION_OCCURRED + AUTHENTICATION_SERVICE_TAG + ", errorMessage : {}";
	public static final String    AUTHENTICATION_SERVICE_ERROR_LOG_WITH_MESSAGE_TAG =  "{}" + AUTHENTICATION_SERVICE_TAG ;
	public static final String    AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG=  EXCEPTION_OCCURRED +  AUTHENTICATION_SERVICE_TAG  + ", errorMessage : {}, stackTrace : {}";

	private LoggerConstants() {
		throw new IllegalStateException("LoggerConstants class");
	}
}

