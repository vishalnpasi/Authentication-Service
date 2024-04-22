package com.albanero.authservice.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.albanero.authservice.model.ChangeSecSettings;

/**
 * Repository class for database transactions with DaoUser Collection
 * 
 * @author arunima.mishra
 */
@Repository
public interface UserSecRepository extends MongoRepository<ChangeSecSettings, String> {
	public ChangeSecSettings findByUserId(String userId);
	
	public Optional<ChangeSecSettings> findById(String id);
		
	public ChangeSecSettings findByResetCode(String resetCode);
}
