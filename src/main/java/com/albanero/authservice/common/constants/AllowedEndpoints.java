package com.albanero.authservice.common.constants;

public class AllowedEndpoints {
    // end points allowed to access without token

    private static final String[] ALLOWED_ENDPOINTS = {

            MappingConstants.ACTUATOR,
            MappingConstants.API_BASE + AuthConstants.AUTHENTICATE,
            MappingConstants.API_USER_BASE + UserMappingConstants.USER,
            MappingConstants.API_USER_BASE + UserMappingConstants.SAVER_TOKEN,
            MappingConstants.API_USER_BASE + UserMappingConstants.CHANGE_PASSWORD,
            MappingConstants.API_USER_BASE + UserMappingConstants.CHECK_PASSCODE,
            MappingConstants.API_USER_BASE + UserMappingConstants.ADD_PASSCODE,
            MappingConstants.API_USER_BASE + UserMappingConstants.ADD_PASSWORD,
            MappingConstants.API_USER_BASE + UserMappingConstants.VERIFY_USERNAME,
            MappingConstants.API_USER_BASE +UserMappingConstants.VERIFY_EMAIL,
            MappingConstants.API_USER_BASE + UserMappingConstants.VERIFY_USER,  //api to verify the email of a user via email
            MappingConstants.API_USER_BASE + UserMappingConstants.APPROVE_USER,
            MappingConstants.API_USER_BASE + UserMappingConstants.REQUEST_USER_APPROVAL,
            MappingConstants.API_USER_BASE + UserMappingConstants.GENERATE_MFA_QR_AND_SECRET,
            MappingConstants.API_USER_BASE + UserMappingConstants.VERIFY_ORG,
            MappingConstants.API_USER_BASE + OrgConstants.ORG_MEMBER,
            MappingConstants.API_BASE + AuthConstants.VERIFY_MFA,
            "/auth-user/api/add-submodules-to permission",
            "/actuator/refresh",
            MappingConstants.API_USER_BASE + "/revamp-view-download-file",
            MappingConstants.API_BASE + AuthConstants.SECURITY_CHECKS + PathVariables.USERNAME_PARAM1,
            MappingConstants.API_BASE + AuthConstants.VALIDATE_REFRESH_TOKEN, //to check validity of refresh token and generate new access token
            MappingConstants.API_BASE + AuthConstants.GENERATE_NEW_ACCESS_TOKEN, //to generate new access token from valid refresh token
            MappingConstants.API_USER_BASE + UserMappingConstants.USERMAIL + PathVariables.MAIL_ID_PARAM, //used by RBA to get user details based on mailId
            MappingConstants.API_USER_BASE + UserMappingConstants.DELETE_SECURITY_SETTINGS + PathVariables.ID_PARAM,//used by RBA to delete security settings
            MappingConstants.API_BASE + AuthConstants.RESET_FAILED_ATTEMPTS + PathVariables.ID_PARAM, //used by RBA to reset failed attempts after moderate risk verification
            MappingConstants.API_USER_BASE + UserMappingConstants.REQUEST_UNBLOCK,
            MappingConstants.API_USER_BASE + UserMappingConstants.UNBLOCK_USER,
            MappingConstants.API_BASE + AuthConstants.AUTHENTICATE_PASSCODE, //to authenticate otp passcode for moderate risk user
            MappingConstants.API_BASE + AuthConstants.GENERATE_INTERNAL_TOKEN,   //might be used by python services to generate a token,
            MappingConstants.API_USER_BASE + UserMappingConstants.RESEND_VERIFICATION_LINK,
            //API_USER_BASE + UserConstants.VALIDATE_USER,  //used for google login
            //API_USER_BASE + UserConstants.USER + PathVariables.USERNAME_PARAM1,  //code commented
            //API_USER_BASE + UserConstants.USERMAIL + PathVariables.MAIL_ID_PARAM,  //doughtfull   not there in iam sheet
            //API_USER_BASE + UserConstants.USERMAIL,  //code commented
            //API_USER_BASE + UserConstants.USER, //duplicate
            //API_USER_BASE + UserConstants.GOOGLE_AUTH_USER,  //api to register or login a user by google
            //API_BASE + AuthConstants.GENERATE_TOKEN + PathVariables.USERNAME_PARAM,  //probably for api for schedules in worflow
            //API_BASE + AuthConstants.CHECK_FOR_MFA,   //auth token can be generated for the user  used in google login
            //API_BASE + AuthConstants.CHECK_FOR_SQ, API_BASE + AuthConstants.VALIDATE_SECURITY_QUESTION,  //security questions not used

            //API_USER_BASE + UserConstants.USER_DETAILS + PathVariables.USERNAME_PARAM1, //not sure where this api is being used
            //API_BASE + AuthConstants.VALIDATE_ACCESS_TOKEN,  //token is being passed in the headers
//			"/configuration/ui",   //not sure on these apis where are they being used
//			"/swagger-resources",
//			"/configuration/security",
//			"/swagger-ui.html",
//			"/webjars/**",
//			"/v2/api-docs",
            //API_USER_BASE + UserConstants.FETCH_USER_MAPPINGS,   //can be removed..using jwt token
            //API_BASE + AuthConstants.SECURITY_CHECKS + PathVariables.USERNAME_PARAM1,  //being used from from google login. magic auth ...
            //API_USER_BASE + UserConstants.DELETE_SECURITY_SETTINGS + PathVariables.ID_PARAM, //should be authenticated
            //API_BASE + AuthConstants.AUTHENTICATE_MFA,   //meight be used in other micro services
            MappingConstants.API_BASE + AuthConstants.INCREMENT_FAILED_ATTEMPTS + PathVariables.ID_PARAM, //this might be used in google auth or magic link
            //API_BASE + AuthConstants.RESET_FAILED_ATTEMPTS + PathVariables.ID_PARAM, //this might be used in google auth or magic link
            //API_USER_BASE + UserConstants.PROFILE_IMAGE, //token is there
            //API_USER_BASE + PermissionConstants.FEED_ENDPOINT, //can be removed
            //API_USER_BASE + AuthConstants.AUTHORIZE_API_ROUTES, //can be removed
            //API_USER_BASE + "/add-org-watcher-to-users"
    };

    private AllowedEndpoints(){

    }

    public static String[] getAllowedEndPoints() {
        return ALLOWED_ENDPOINTS;
    }
}
