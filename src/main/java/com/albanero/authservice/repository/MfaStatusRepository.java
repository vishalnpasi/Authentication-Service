package com.albanero.authservice.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.albanero.authservice.model.MfaStatus;


@Repository
public interface MfaStatusRepository extends MongoRepository<MfaStatus, String> {

	public MfaStatus findByUserId(String userId);

	public void deleteByUserId(String userId);
}
