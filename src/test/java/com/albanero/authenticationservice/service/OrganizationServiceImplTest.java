//package com.albanero.authenticationservice.service;
//
//import com.albanero.authservice.common.dto.response.BaseResponse;
//import com.albanero.authservice.controller.OrganizationController;
//import com.albanero.authservice.repository.OrgRepository;
//import com.albanero.authservice.service.OrganizationService;
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
//class OrganizationServiceImplTest {
//    private static final Logger LOGGER = LoggerFactory.getLogger(OrganizationServiceImpl.class);
//
//    @Autowired
//    OrgRepository orgRepository;
//
//    @Autowired
//    private OrganizationService organizationService;
//
//    @Autowired
//    private OrganizationController organizationController;
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
//    void fetchOrganizationDetails_Test() {
//        try {
//            BaseResponse response = organizationService.fetchOrganizationDetails("639c774543620e746d93a126");
//            ResponseEntity<BaseResponse> responseResponseEntity = organizationController.fetchOrganizationDetails("639c774543620e746d93a126");
//            assertEquals(HttpStatus.OK, response.getStatusCode());
//            BaseResponse baseResponse = responseResponseEntity.getBody();
//            assertEquals(HttpStatus.OK, baseResponse.getStatusCode());
//        } catch (Exception e) {
//            LOGGER.error("Inside OrganizationServiceImplTest::fetchOrganizationDetails_Test method : Unknown error {} ",
//                    e.getMessage(), e);
//        }
//    }
//}
