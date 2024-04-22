package com.albanero.authservice.common.constants;

public enum EmailConstants {
    PLATFORM_OPS("platform-ops@albanero.io"),
    ALBANERO("Albanero"),
    NAME("[[name]]"),
    FALSE("/false"),
    TRUE("/true"),
    DEAR_NAME("Dear [[name]],<br>"),
    YES("[[YES]]"),
    NO("[[NO]]"),
    THANK_YOU("Thank you,<br>"),
    ALBANERO_ADMIN("Albanero Admin"),
    VERIFY_URL("/auth-verify/user/api/user/approve-account/"),
    CHOOSE_BELOW_LINK("Please choose the below links to approve/disapprove the given user account for Organization - "),
    APPROVE("<h3><a href=\"[[YES]]\" target=\"_self\">Approve</a></h3>"),
    DISAPPROVE("<h3><a href=\"[[NO]]\" target=\"_self\">Disapprove</a></h3>"),
    APPROVED ("approved"),
    ACTIVATED("activated");

    public final String label;

    EmailConstants(String label) {
        this.label = label;
    }

    @Override
    public String toString() {
        return this.label;
    }
}
