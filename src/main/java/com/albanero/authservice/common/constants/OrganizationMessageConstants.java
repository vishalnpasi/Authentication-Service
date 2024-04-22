package com.albanero.authservice.common.constants;

public enum OrganizationMessageConstants {
    INVALID_ORG("Invalid Organization!"),
    ORG_EMPTY("Given OrgId is either empty or null!"),
    INVALID_TOKEN("Invalid Token!"),
    COULD_NOT_VALIDATE_ORG("Could not validate organization or fetch product details!"),
    ORGANIZATION_SERVICE_EXCEPTION("Exception occurred in Organization Service"),
    INVALID_EMAIL("The given user's email is either null or invalid!"),
    ROLE_EMPTY("Given role is null!"),
    MEMBER_ROLE_DONT_EXIST("Given member role does not exist!"),
    MEMBER_ORG_DONT_EXIST("Given organization does not exist!"),
    USER_ADDED("User Added"),
    USER_ALREADY_MEMBER("User is already a member."),
    USER_ALREADY_REGISTER("User is already registered."),
    USERNAME_EMPTY("The given user's username is either empty or null!"),
    USERMAIL_EMPTY("The given user's email is either empty or null!"),
    INVALID_USERNAME("Username is Invalid!"),
    INVALID_FIRSTNAME("First Name is Invalid!"),
    INVALID_LASTNAME("Last Name is Invalid!"),
    INVALID_PASSWORD("Given user password is not valid!"),
    PASSWORD_MISMATCH("Password fields do not match!"),
    AUTH_HISTORY_NOT_SAVE("Error occured while saving user auth history"),
    ORGANIZATION_NOT_FOUND("Organization does not exist."),
    INVALID_ADMIN_EMAIL("Invalid admin email"),
    USER_ORGANIZATION_NOT_FOUND("User Organization not found"),
    PRODUCT_LIST_NOT_FOUND("Product list not fond."),
    VALID_ORGANIZATION("Valid Organization and the product details fetched!"),
    ORGANIZATION_DETAILS_FETCHED("Organization details fetched!"),
    USER_FETCH_EXCEPTION("Exception occurred while fetching users"),
    INCOMPLETE_ORGANIZATION_DETAILS("Not enough organization details provided"),
    ORG_ADMIN_ROLE_NOT_FOUND("Organization Admin Role not found"),
    ORG_NAME_NOT_VALID("Organization name is not valid"),
    ORG_URL_NOT_VALID("Organization url is not valid"),
    VALID_PRODUCT_ID("Please send valid product IDs"),
    ORGANIZATION_CREATION_SUCCESSFUL("Successfully created the Organization!"),
    INVALID_ROLE_TO_CREATE_ORGANIZATION("This user doesn't have the permissions to create organization"),
    VALID_ORG("Valid Organization!"),
    DUPLICATE_ORGANIZATION("Organization exists with same name"),
    ACTION_FAILED("Action Failed"),
    PRODUCT_NOT_FOUND("Product not found with given Org Details.");
    public final String label;

    OrganizationMessageConstants(String s) {
        this.label = s;
    }
    @Override
    public String toString() {
        return this.label;
    }
}
