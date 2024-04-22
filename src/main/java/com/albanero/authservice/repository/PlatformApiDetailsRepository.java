package com.albanero.authservice.repository;

import java.util.List;


import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import com.albanero.authservice.model.PlatformApiDetails;

@Repository
public interface PlatformApiDetailsRepository extends MongoRepository<PlatformApiDetails, String> {
	
	@Query("{ 'apiRoute' : { $regex: ?0 }, 'apiMethod' : ?1 }")
	public List<PlatformApiDetails> findByApiRouteAndApiMethod(String apiRoute, String apiMethod);


	@Query(value = "{ 'apiRoute' : ?0, 'apiMethod' : ?1 }", fields = "{ '_id': 1 }")
	public PlatformApiDetails findIdByApiRouteAndApiMethod(String apiRoute, String apiMethod);

	
}
