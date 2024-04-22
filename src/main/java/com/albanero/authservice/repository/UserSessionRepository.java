package com.albanero.authservice.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.albanero.authservice.model.UserSession;

/**
 * Repository class for database transactions with DaoUser Collection
 * 
 * @author arunima.mishra
 */
@Repository
public interface UserSessionRepository extends MongoRepository<UserSession, String> {
	public UserSession findByUserId(String userId);
	
	public Optional<UserSession> findById(String id);
	
	public UserSession findByHashedRT(String token);

}
