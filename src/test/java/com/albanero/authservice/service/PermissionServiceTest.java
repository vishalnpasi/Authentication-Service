//package com.albanero.authservice.service;
//
//import com.albanero.authservice.common.dto.request.CustomRole;
//import com.albanero.authservice.common.dto.response.BaseResponse;
//import com.albanero.authservice.model.Modules;
//import com.albanero.authservice.model.UserProfile;
//import com.albanero.authservice.repository.UserRepository;
//import com.albanero.authservice.service.impl.PermissionServiceImpl;
//import org.junit.Test;
//import org.mockito.Mockito;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.mock.mockito.MockBean;
//
//import jakarta.servlet.http.HttpServletRequest;
//
//import static org.junit.jupiter.api.Assertions.assertEquals;
//
//public class PermissionServiceTest {
//
//    private static final Logger LOGGER = LoggerFactory.getLogger(PermissionServiceTest.class);
//
//    @Autowired
//    PermissionServiceImpl permissionService;
//    @MockBean
//    private HttpServletRequest request;
//
//    @Test
//    void getPermissionTest() {
//        try {
//            LOGGER.info("Inside PermissionServiceTest::getPermissionTest method");
//            BaseResponse response = permissionService.getPermissions();
//            assertEquals(true, response.getSuccess());
//        } catch (Exception e) {
//            LOGGER.error("Inside PermissionServiceTest::getPermissionTest method : Unknown error {} ",
//                    e.getMessage(), e);
//        }
//    }
//
//    @Test
//    void customRoleTest() {
//        try {
//            LOGGER.info("Inside PermissionServiceTest::customRoleTest method");
//            BaseResponse response = permissionService.saveCustomRole(request, Mockito.mock(CustomRole.class));
//            assertEquals(true, response.getSuccess());
//        } catch (Exception e) {
//            LOGGER.error("Inside PermissionServiceTest::customRoleTest method : Unknown error {} ",
//                    e.getMessage(), e);
//        }
//    }
//
//    @Test
//    void permissionTreeTest() {
//        try {
//            LOGGER.info("Inside PermissionServiceTest::permissionTreeTest method");
//            BaseResponse response = permissionService.getPermissionTree();
//            assertEquals(true, response.getSuccess());
//        } catch (Exception e) {
//            LOGGER.error("Inside PermissionServiceTest::customRoleTest method : Unknown error {} ",
//                    e.getMessage(), e);
//        }
//    }
//
//    @Test
//    void updateRoleTest() {
//        try {
//            LOGGER.info("Inside PermissionServiceTest::updateRoleTest method");
//            BaseResponse response = permissionService.updateRole(request, Mockito.mock(String.class), Mockito.mock(CustomRole.class));
//            assertEquals(true, response.getSuccess());
//        } catch (Exception e) {
//            LOGGER.error("Inside PermissionServiceTest::updateRoleTest method : Unknown error {} ",
//                    e.getMessage(), e);
//        }
//    }
//
//    @Test
//    void getRoleTest() {
//        try {
//            LOGGER.info("Inside PermissionServiceTest::getRoleTest method");
//            BaseResponse response = permissionService.getRole(request, Mockito.mock(String.class));
//            assertEquals(true, response.getSuccess());
//        } catch (Exception e) {
//            LOGGER.error("Inside PermissionServiceTest::getRoleTest method : Unknown error {} ",
//                    e.getMessage(), e);
//        }
//    }
//
//    @Test
//    void createModule_Test() {
//        try {
//            LOGGER.info("Inside PermissionServiceTest::createModule_Test method");
//            Modules modules = new Modules();
//            modules.setModuleName("test module");
//            BaseResponse response = permissionService.createModule(request, modules);
//            assertEquals(true, response.getSuccess());
//        } catch (Exception e) {
//            LOGGER.error("Inside PermissionServiceTest::createModule_Test method : Unknown error {} ",
//                    e.getMessage(), e);
//        }
//    }
//
//    @Test
//    void editModule_Test() {
//        try {
//            LOGGER.info("Inside PermissionServiceTest::editModule_Test method");
//            Modules modules = new Modules();
//            modules.setModuleName("test module");
//            BaseResponse response = permissionService.editModule(request, modules, "63c8ef5afdb86f74955b2e6c");
//            assertEquals(true, response.getSuccess());
//        } catch (Exception e) {
//            LOGGER.error("Inside PermissionServiceTest::editModule_Test method : Unknown error {} ",
//                    e.getMessage(), e);
//        }
//    }
//
//    @Test
//    void getPermissionModules_Test() {
//        try {
//            LOGGER.info("Inside PermissionServiceTest::getPermissionModules_Test method");
//            BaseResponse response = permissionService.permissionModules(request,0,10);
//            assertEquals(true, response.getSuccess());
//        } catch (Exception e) {
//            LOGGER.error("Inside PermissionServiceTest::getPermissionModules_Test method : Unknown error {} ",
//                    e.getMessage(), e);
//        }
//    }
//
//    @Test
//    void getPermissionModule_Test(){
//        try {
//            LOGGER.info("Inside PermissionServiceTest::getPermissionModule_Test method");
//            BaseResponse response = permissionService.fetchModule("63c8ef5afdb86f74955b2e6c");
//            assertEquals(true, response.getSuccess());
//        } catch (Exception e) {
//            LOGGER.error("Inside PermissionServiceTest::getPermissionModule_Test method : Unknown error {} ",
//                    e.getMessage(), e);
//        }
//    }
//}
