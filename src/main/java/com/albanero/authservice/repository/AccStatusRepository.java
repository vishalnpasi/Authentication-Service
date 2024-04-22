package com.albanero.authservice.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import com.albanero.authservice.model.AccountStatus;


/**
 * Repository class for database transactions with DaoUser Collection
 * 
 * @author arunima.mishra
 */
@Repository
public interface AccStatusRepository extends MongoRepository<AccountStatus, String> {
    public AccountStatus findByUserId(String userId);
	
	public Optional<AccountStatus> findById(String id);

	public List<AccountStatus> findByUserIdIn(List<String> userId);

	public void deleteByUserId(String userId);

	@Query("{'emailStatus.verificationCode':?0}")
	public AccountStatus findByVerificationCode(String verificationCode);
}
