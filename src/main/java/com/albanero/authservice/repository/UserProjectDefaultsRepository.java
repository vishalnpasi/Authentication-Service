package com.albanero.authservice.repository;

import com.albanero.authservice.model.UserProjectDefaults;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;


/**
 * Repository class for database transactions with UserProjectDefaults Collection
 */
@Repository
public interface UserProjectDefaultsRepository extends MongoRepository<UserProjectDefaults, String> {
    @Query("{'userId': ?0 }")
    public UserProjectDefaults findByUserId(String userId);

    @Query("{'userId': ?0, 'orgId': ?1 }")
    public UserProjectDefaults findByUserIdAndOrgId(String userId, String orgId);

}
