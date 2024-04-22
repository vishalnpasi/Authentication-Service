package com.albanero.authservice.repository;

import com.albanero.authservice.model.Modules;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.stereotype.Repository;


@Repository
@EnableMongoRepositories
public interface ModuleRepository extends MongoRepository<Modules, String> {
    public Modules findByModuleName(String moduleName);
}
