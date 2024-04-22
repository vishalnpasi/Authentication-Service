package com.albanero.authservice.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.albanero.authservice.model.Project;

@Repository
public interface ProjectRepository extends MongoRepository<Project, String>{

	public Project findByProjectUrl(String projectUrl);
}
