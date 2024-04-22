package com.albanero.authservice.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.mongodb.config.AbstractMongoClientConfiguration;

public class MongoConfig extends AbstractMongoClientConfiguration {


    @Value("${spring.data.mongodb.database.global}")
    private String mongoDatabaseName;


    @Override
    protected String getDatabaseName() {
        return mongoDatabaseName;
    }

    @Override
    protected boolean autoIndexCreation(){
        return true;
    }
}