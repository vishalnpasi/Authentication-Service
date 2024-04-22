//package resources;
//
//import com.albanero.authservice.common.dto.response.BaseResponse;
//import com.albanero.authservice.common.util.RequestUtil;
//import com.albanero.authservice.model.*;
//import com.albanero.authservice.repository.AccStatusRepository;
//import com.albanero.authservice.repository.OrgRoleRepository;
//import com.albanero.authservice.repository.UserOrgRoleRepository;
//import com.albanero.authservice.repository.UserRepository;
//import org.mockito.Mock;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.boot.test.mock.mockito.MockBean;
//import org.springframework.stereotype.Repository;
//
//import jakarta.servlet.http.HttpServletRequest;
//import java.util.ArrayList;
//import java.util.HashMap;
//import java.util.List;
//
//import static org.mockito.Mockito.when;
//
//@Repository
//public class MockRepositories {
//
//    private static final Logger LOGGER = LoggerFactory.getLogger(MockRepositories.class);
//
//    @MockBean
//    private OrgRoleRepository orgRoleRepository;
//
//    @MockBean
//    private UserOrgRoleRepository userOrgRoleRepo;
//
//    @MockBean
//    private RequestUtil requestUtil;
//
//    @MockBean
//    private UserRepository userRepository;
//
//    @MockBean
//    private AccStatusRepository accStatusRepository;
//
//
//    public void mock() {
//        LOGGER.info("Stared mocking.....");
//
//        LOGGER.info("SET OrganizationRoleRepository");
//        List<OrganizationRole> organizationRoleList = new ArrayList<OrganizationRole>();
//        OrganizationRole organizationRole = new OrganizationRole();
//        organizationRole.setId("7896");
//        organizationRole.setOrgId("1236");
//        organizationRole.setRoleId("1147");
//        organizationRoleList.add(organizationRole);
//        when(orgRoleRepository.findByOrgId("62bd7c7facd31950f86d82d")).thenReturn((organizationRoleList));
//
//        LOGGER.info("SET UserOrgRoleRepository");
//        List<String> orgRoleIdList = new ArrayList<>();
//        orgRoleIdList.add("7896");
//        List<UserOrgRole> userOrgRoleList = new ArrayList<>();
//        UserOrgRole userOrgRole = new UserOrgRole();
//        userOrgRole.setId("7896");
//        userOrgRole.setUserId("125");
//        userOrgRoleList.add(userOrgRole);
//        when(userOrgRoleRepo.findByOrgRoleIdListIn(orgRoleIdList)).thenReturn(userOrgRoleList);
//
//        LOGGER.info("SET UserOrgRoleRepository");
//        List<String> userIds = new ArrayList<>();
//        userIds.add("125");
//        ArrayList<Object> usersBlockStatus = new ArrayList<>();
//        HashMap<String, Object> userBlockStatus = new HashMap<>();
//        userBlockStatus.put("userid", "125");
//        userBlockStatus.put("status", true);
//        usersBlockStatus.add(userBlockStatus);
//        BaseResponse baseResponse = new BaseResponse();
//        baseResponse.setSuccess(true);
//        baseResponse.setPayload(usersBlockStatus);
//        when(requestUtil.getUsersBlockStatus(userIds)).thenReturn(baseResponse);
//
//        LOGGER.info("SET UserRepository");
//        UserProfile user = new UserProfile();
//        user.setId("125");
//        when(userRepository.findById("125")).thenReturn(java.util.Optional.of(user));
//
//        LOGGER.info("SET accStatusRepository");
//        AccountStatus accountStatus = new AccountStatus();
//        AccountApprovalStatus accountApprovalStatus = new AccountApprovalStatus();
//        accountApprovalStatus.setIsAccountApproved(true);
//        accountStatus.setAccountApprovalStatus(accountApprovalStatus);
//        AccountActivationStatus accountActivationStatus = new AccountActivationStatus();
//        accountActivationStatus.setIsActive(true);
//        accountStatus.setAccountActivationStatus(accountActivationStatus);
//        when(accStatusRepository.findByUserId("125")).thenReturn(accountStatus);
//
//        LOGGER.info("Docking is Done.......");
//    }
//}
