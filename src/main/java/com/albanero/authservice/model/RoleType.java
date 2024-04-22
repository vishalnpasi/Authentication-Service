package com.albanero.authservice.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import org.springframework.data.mongodb.core.mapping.Field;

import java.util.List;

@Data
@Document(collection = "role")
public class RoleType {
    @Id
    private String id;
    @NotBlank
    @Field(name = "roleType")
    private String roleTypeName;
    @NotEmpty
    private List<String> projectId;
    @NotEmpty
    private List<String> orgId;
}
