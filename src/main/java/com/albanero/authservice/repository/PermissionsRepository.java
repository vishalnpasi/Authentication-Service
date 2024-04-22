package com.albanero.authservice.repository;

import org.springframework.data.mongodb.repository.Aggregation;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.albanero.authservice.model.Permissions;

import java.util.List;

@Repository
public interface PermissionsRepository extends MongoRepository<Permissions, String> {
    public Permissions getByPermissionAndScreen(String permission, String screen);

    List<Permissions> findByModuleId(String id);

    List<Permissions> findBySubModuleId(String id);

    Permissions findByPermissionTitleAndModuleIdAndSubModuleId(String permissionTitle, String moduleId, String subModuleId);

    List<Permissions> findByModuleIdAndSubModuleId(String moduleId, String subModuleId);

    Permissions findByPermissionTitleAndModuleId(String permissionTitle, String moduleId);

    @Aggregation(pipeline = {
            "{$unwind: '$allowedEndpointIdList'}",
            "{$match: {'allowedEndpointIdList': {$ne: ?0}}}",
            "{$group: {'_id': '$_id', 'allowedEndpointIdList': {$push: '$allowedEndpointIdList'}, " +
                    "'screen':{$first:'$screen'}, 'description':{$first:'$description'}, " +
                    "'permissionTitle':{$first:'$permissionTitle'},'subModuleId':{$first:'$subModuleId'}," +
                    "'moduleId':{$first:'$moduleId'},'permission':{$first:'$permission'}}}",
            "{$set: {'allowedEndpointIdList': '$allowedEndpointIdList'}}"
    })
    List<Permissions> removeEndpointIds(String removeId);
}
