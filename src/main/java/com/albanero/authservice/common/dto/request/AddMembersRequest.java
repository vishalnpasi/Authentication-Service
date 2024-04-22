package com.albanero.authservice.common.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.util.List;


@Data
@Schema(description = "Add Member Request DTO class for adding multiple org member API Calls")
public class AddMembersRequest {
    @Schema(description = "details of org members")
    List<MembersDetailsRequest> membersDetails;
    @Schema(description = "Organisation Id of org member")
    String orgId;
    @Schema(description = "Project ID")
    String projectId;
}
