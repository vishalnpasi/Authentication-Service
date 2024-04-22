package com.albanero.authservice.repository;

import com.albanero.authservice.model.SubModules;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@EnableMongoRepositories
public interface SubModuleRepository extends MongoRepository<SubModules, String> {
    SubModules findBySubModuleName(String subModuleName);

    List<SubModules> findByModuleId(String id);

    SubModules findBySubModuleNameAndModuleId(String subModule, String moduleId);
}
