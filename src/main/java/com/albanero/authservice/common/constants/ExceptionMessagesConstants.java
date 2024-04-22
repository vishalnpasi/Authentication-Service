package com.albanero.authservice.common.constants;

public enum ExceptionMessagesConstants {

    // Authentication Service Exceptions

    USER_LOGOUT_EXCEPTION("You have been logged out!"),
    ROLE_NOT_ASSIGNED_EXCEPTION("There is no role assigned to this user!"),
    INVALID_CRED_OR_TOKEN_EXCEPTION("Either the credentials are empty or the token sent is incorrect!"),
    IP_BLOCK_EXCEPTION("User can't Login because this IP is blocked!"),
    SECURITY_QUESTION_VERIFY_EXCEPTION("The user is required to go for Security Question Verification."),
    OTP_VERIFICATION_EXCEPTION("The user is required to go for OTP Verification."),

    // Permission Service Exceptions

    SUB_MODULE_NOT_BELONG_MODULE("Sub Module does not belong to the module"),
    ROLE_NOT_EXIST_EXCEPTION("Role Doesn't exist"),
    INVALID_ROUTE_REGEX_EXCEPTION("Api Route is not a valid regex"),
    INVALID_API_METHOD_EXCEPTION("Api Method is not a valid one"),
    CUSTOM_ROLE_TYPE_EXCEPTION("The role type should be custom"),
    ROLE_DESCRIPTION_NULL_EXCEPTION("Role description cannot be null"),
    DUPLICATE_ROLE_NAME_EXCEPTION("Role Name already taken. Please select a different role name or update the existing role"),
    UNABLE_UPDATE_ROLE_EXCEPTION("This role is not created by you so you cannot update it"),
    NO_MODULE_FOUND("No module found with the given name. Module name : "),
    NO_ROLE_FOUND("No role found with the given name. Role name : "),
    NO_PERMISSION_FOUND("No permission found with the given name. Permission name : "),
    NO_SUBMODULE_FOUND("No subModule found with the given name. Sub Module name : "),
    NO_PLATFORM_API_DETAILS_FOUND("No platformApiDetails found with this api route : "),
    API_ROUTE(" apiRoute and "),
    MODULE_NAME(" moduleName."),
    ROLE_NAME(" roleName."),
    PERMISSION_TITLE(" permissionTitle, "),
    MODUELID(" moduleId and "),
    SUBMODULEID(" subModuleId."),
    SUBMODULE_NAME("subModuleName."),
    APIMETHOD(" apiMethod."),

    // RAB Service Exception

    RISK_LEVE_CALCULATION_ERROR("Error occurred while calculating risk level"),
    RBA_SERVICE_EXCEPTION("Exception occurred in RBA Service"),
    QR_GEN_EXCEPTION_IN_IP_BLOCK("New QR cannot be generated because this IP is blocked"),


    // Token Service Exception

    TOKEN_SERVICE_EXCEPTION("Exception occurred in Token Service"),

    // User Service Exception

    USER_NOT_FOUND_EXCEPTION("User not found with the name "),
    EITHER_USER_ID_OR_PROJECT_ID_IS_INVALID("Either user id or project id is invalid."),
    USER_ID_IS_NULL_OR_NOT_PROVIDED("UserId is not given or not provided."),
    USER_NOT_FOUND_WITH_ID_EXCEPTION("User not found with the UserId"),
    ORG_ID_IS_NOT_PRESENT_EXCEPTION("OrgId is not present"),
    PROJECT_ID_IS_NOT_PRESENT_EXCEPTION("ProjectId is not present"),
    INVALID_ORG_ID_EXCEPTION("Invalid orgId"),
    USER_PROJECT_DETAILS_NOT_EXIST("User project details doesn't exist."),
    INVALID_PROJECT_ID_EXCEPTION("Invalid projectId"),
    INVALID_USER_NAME_EXCEPTION("Given username is not valid!"),
    INVALID_EMAIL_AS_USERNAME_EXCEPTION("You cannot use a different email as username!"),
    INVALID_USER_PASSWORD_EXCEPTION("Password is not valid!"),
    PASSWORD_FIELDS_EXCEPTION("Password fields do not match!"),
    INVALID_USER_EMAIL_EXCEPTION("Given user email is not valid!"),
    DUPLICATE_USERNAME_AND_EMAIL_EXCEPTION("A user already exists with the given identities"),
    INVALID_FIRST_NAME_EXCEPTION("First name is invalid"),
    INVALID_LAST_NAME_EXCEPTION("Last name is invalid"),
    AUTH_HISTORY_SAVING_EXCEPTION("Error occured while saving user auth history"),
    ORIGIN_NULL_EXCEPTION("API origin is null"),
    INVALID_OTP_EXCEPTION("OTP has expired"),
    EMPTY_REQUEST_BODY_EXCEPTION("FirstName, LastName and Email should not be empty!"),
    PROJECT_ID_INVALID_EXCEPTION("ProjectId in Invalid"),
    MEMBER_ORG_ROLE_DONT_EXIST("Given organization or member role does not exist!"),
    ROLE_IS_NOT_ASSOCIATED_TO_PROJECT_EXCEPTION("Given role is not associated to the project"),
    OTP_EXPIRED_EXCEPTION("Otp has expired"),
    NOT_AUTHORIZED_TO_APPROVE_EXCEPTION("You are not authorised to approve this request"),

    // Request Util

    INVALID_RT_TOKEN_EXCEPTION("Invalid request token"),

    // EMAIL Util

    ACTIVATION_MAIL_EXCEPTION("Action Failed!, While sending email for account activation"),
    MFA_RESET_QR_MAIL_EXCEPTION("Action Failed!, while sending email for Rest MFA QR"),

    // Common Exception

    ACTION_FAILED_EXCEPTION("Action Failed"),
    OPT_EXPIRED_EXCEPTION("OTP has expired"),
    HTTP_REST_API_IS_UNAUTHORIZED("HTTP REST API is Unauthorized"),
    USER_DOES_NOT_EXISTS("This user account does not exist."),
    INVALID_AUTH_TOKEN("Invalid Auth token!"),
    ACTION_FAILED("Action Failed"),
    GIVEN_USER_PASSWORD_IS_NOT_VALID("Given user password is not valid!"),


    //Invalid refresh token exception
    INVALID_REFRESH_TOKEN_EXCEPTION("Invalid refresh token");

    public final String label;

    ExceptionMessagesConstants(String label) {
        this.label = label;
    }

    @Override
    public String toString() {
        return this.label;
    }
}

