package com.albanero.authservice.repository;


import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import com.albanero.authservice.model.UserProfile;

/**
 * Repository class for database transactions with DaoUser Collection
 * 
 * @author arunima.mishra
 */
@Repository
public interface UserRepository extends MongoRepository<UserProfile, String> {
	public UserProfile findByUsername(String username);
	
	public UserProfile findByEmailId(String emailId);
	
	@Query("{$or:[{'username':?0}, {'emailId':?0}]}")
	public UserProfile findByEmailOrUserName(String usernameOrEmail);
}
