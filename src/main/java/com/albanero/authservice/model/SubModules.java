package com.albanero.authservice.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document(collection = "subModules")
public class SubModules {
    @Id
    String id;
    String subModuleName;
    @Indexed
    String moduleId;
}
