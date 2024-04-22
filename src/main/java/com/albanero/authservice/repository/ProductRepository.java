package com.albanero.authservice.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.albanero.authservice.model.Product;

@Repository
public interface ProductRepository extends MongoRepository<Product, String> {

	public Optional<Product> findById(String id);
	
	public Product findByName(String name);

}
