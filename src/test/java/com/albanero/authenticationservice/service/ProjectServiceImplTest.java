//package com.albanero.authenticationservice.service;
//
//import com.albanero.authservice.common.dto.response.BaseResponse;
//import com.albanero.authservice.controller.ProjectController;
//import com.albanero.authservice.repository.ProjectRepository;
//import com.albanero.authservice.service.ProjectService;
//import com.albanero.authservice.service.impl.OrganizationServiceImpl;
//import org.junit.jupiter.api.Test;
//import org.junit.runner.RunWith;
//import org.mockito.Mock;
//import org.mockito.junit.MockitoJUnitRunner;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.context.SpringBootTest;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//
//import static org.junit.Assert.assertEquals;
//
//@SpringBootTest
//@RunWith(MockitoJUnitRunner.class)
//class ProjectServiceImplTest {
//    private static final Logger LOGGER = LoggerFactory.getLogger(OrganizationServiceImpl.class);
//
//    @Autowired
//    ProjectRepository projectRepository;
//
//    @Autowired
//    private ProjectService projectService;
//
//    @Autowired
//    private ProjectController projectController;
//
//    @Mock
//    private HttpServletRequest request;
//
//    @Mock
//    private HttpServletResponse response;
//
//    @Test
//    void contextLoads() {
//    }
//
//    @Test
//    void fetchUserProjects_Test() {
//        try {
//            BaseResponse response = projectService.fetchUserProjects(request);
//            ResponseEntity<BaseResponse> responseResponseEntity = projectController.fetchUserDefaultProject(request, "62b5e65feec2a0aac7b94a71");
//            assertEquals(HttpStatus.OK, response.getStatusCode());
//            BaseResponse baseResponse = responseResponseEntity.getBody();
//            assertEquals(HttpStatus.OK, baseResponse.getStatusCode());
//        } catch (Exception e) {
//            LOGGER.error("Inside ProjectServiceImplTest::fetchUserProjects_Test method : Unknown error {} ",
//                    e.getMessage(), e);
//        }
//    }
//
//    @Test
//    void setUserDefaultProject_Test() {
//        try {
//            BaseResponse response = projectService.setUserDefaultProject(request, "62b5e65feec2a0aac7b94a71", "63033dc14e1f697734d64ccd");
//            ResponseEntity<BaseResponse> responseResponseEntity = projectController.setUserDefaultProject(request, "63033dc14e1f697734d64ccd","62b5e65feec2a0aac7b94a71");
//            assertEquals(HttpStatus.OK, response.getStatusCode());
//            BaseResponse baseResponse = responseResponseEntity.getBody();
//            assertEquals(HttpStatus.OK, baseResponse.getStatusCode());
//        } catch (Exception e) {
//            LOGGER.error("Inside ProjectServiceImplTest::setUserDefaultProject_Test method : Unknown error {} ",
//                    e.getMessage(), e);
//        }
//    }
//
//    @Test
//    void fetchUserDefaultProject_Test() {
//        try {
//            BaseResponse response = projectService.fetchUserDefaultProject(request, "62b5e65feec2a0aac7b94a71");
//            ResponseEntity<BaseResponse> responseResponseEntity = projectController.fetchUserDefaultProject(request,"62b5e65feec2a0aac7b94a71");
//            assertEquals(HttpStatus.OK, response.getStatusCode());
//            BaseResponse baseResponse = responseResponseEntity.getBody();
//            assertEquals(HttpStatus.OK, baseResponse.getStatusCode());
//        } catch (Exception e) {
//            LOGGER.error("Inside ProjectServiceImplTest::fetchUserDefaultProject_Test method : Unknown error {} ",
//                    e.getMessage(), e);
//        }
//    }
//
//    @Test
//    void removeUserDefaultProject_Test() {
//        try {
//            BaseResponse response = projectService.removeUserDefaultProject(request, "62b5e65feec2a0aac7b94a71");
//            ResponseEntity<BaseResponse> responseResponseEntity = projectController.removeUserDefaultProject(request, "62b5e65feec2a0aac7b94a71");
//            assertEquals(HttpStatus.OK, response.getStatusCode());
//            BaseResponse baseResponse = responseResponseEntity.getBody();
//            assertEquals(HttpStatus.OK, baseResponse.getStatusCode());
//        } catch (Exception e) {
//            LOGGER.error("Inside ProjectServiceImplTest::removeUserDefaultProject_Test method : Unknown error {} ",
//                    e.getMessage(), e);
//        }
//    }
//}
