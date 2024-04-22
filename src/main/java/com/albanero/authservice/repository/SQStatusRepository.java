package com.albanero.authservice.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.albanero.authservice.model.SecurityQuestionStatus;

@Repository
public interface SQStatusRepository extends MongoRepository<SecurityQuestionStatus, String> {

	public SecurityQuestionStatus findByUserId(String userId);
}
