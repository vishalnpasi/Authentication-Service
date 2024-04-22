package com.albanero.authservice.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.albanero.authservice.model.SecurityQuestions;

@Repository
public interface SecurityQuestionsRepository extends MongoRepository<SecurityQuestions, String> {

}
