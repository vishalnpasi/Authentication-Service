package com.albanero.authservice.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.albanero.authservice.model.Organization;

/**
 * Repository class for database transactions with Organization Collection
 * 
 * @author arunima.mishra
 */
@Repository
public interface OrgRepository extends MongoRepository<Organization, String> {

	public Optional<Organization> findById(String id);

	public Organization findByName(String name);
	
	public Organization findByOrgUrl(String orgUrl);
	
	public Organization findByNameAndOrgUrl(String name, String orgUrl);
	
	public List<Organization> findAllByOrderByIdAsc();
}
