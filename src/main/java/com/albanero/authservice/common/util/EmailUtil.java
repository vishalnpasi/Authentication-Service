package com.albanero.authservice.common.util;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

import jakarta.mail.*;
import jakarta.mail.internet.MimeMessage;
import jakarta.servlet.http.HttpServletRequest;

import com.albanero.authservice.common.constants.EmailConstants;
import com.albanero.authservice.common.constants.MfaConstants;
import com.albanero.authservice.common.dto.request.AddRemoveMemberRequest;
import com.albanero.authservice.common.dto.request.RegistrationUser;
import com.albanero.authservice.common.dto.response.BaseResponse;
import com.albanero.authservice.common.dto.response.RegisterUserResponse;
import com.albanero.authservice.exception.EmailUtilException;
import com.albanero.authservice.model.*;
import com.albanero.authservice.repository.MfaStatusRepository;
import com.albanero.authservice.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.jasypt.util.text.BasicTextEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import com.albanero.authservice.common.constants.TokenConstants;
import com.albanero.authservice.repository.AccStatusRepository;

import static com.albanero.authservice.common.constants.EmailConstants.*;
import static com.albanero.authservice.common.constants.ExceptionMessagesConstants.*;
import static com.albanero.authservice.common.constants.LoggerConstants.AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG;


@Service
@Slf4j
public class EmailUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(EmailUtil.class);

    private static final String EMAIL_UTIL = "EmailUtil";

    private static final String MAIL_SMTP_HOST= "mail.smtp.host";

    private static final String MAIL_SMTP_PORT= "mail.smtp.port";

    private static final String MAIL_SMTP_AUTH= "mail.smtp.auth";

    private static final String MAIL_SMTP_STARTTLS_ENABLE = "mail.smtp.starttls.enable";


    private final AccStatusRepository accStatusRepo;

    private final MfaStatusRepository mfaRepo;

    private final UserRepository userRepository;

    @Autowired
    public EmailUtil(AccStatusRepository accStatusRepo, UserRepository userRepository, JavaMailSender mailSender,
                     MfaStatusRepository mfaRepo, RequestUtil requestUtil) {

        this.accStatusRepo = accStatusRepo;
        this.userRepository = userRepository;
        this.mailSender = mailSender;
        this.requestUtil = requestUtil;
        this.mfaRepo = mfaRepo;
    }


    @Value("${spring.mail.username}")
    private String mailUsername;

    @Value("${spring.mail.password}")
    private String mailPassword;

    @Value("${spring.mail.host}")
    private String mailHost;

    @Value("${spring.mail.port}")
    private int mailPort;

    @Value("${spring.mail.properties.mail.smtp.starttls.enable}")
    private Boolean mailEnable;

    @Value("${spring.mail.properties.mail.smtp.auth}")
    private Boolean mailAuth;

    @Value("${jasyptSecret}")
	private String encryptorPassword;

    private JavaMailSender mailSender;
   	
   	private RequestUtil requestUtil;

    @Value("${albanero.account.approval.email1}")
    private String email1;

    @Value("${albanero.account.approval.email2}")
    private String email2;

    @Value("${albanero.account.approval.email3}")
    private String email3;

    @Value("${albanero.account.approval.email4}")
    private String email4;

    @Value("${albanero.account.approval.email5}")
    private String email5;

    @Value("${albanero.account.approval.email6}")
    private String email6;

    @Value("${albanero.account.approval.email7}")
    private String email7;

    @Value("${albanero.account.approval.email8}")
    private String email8;

    @Value("${albanero.account.approval.email9}")
    private String email9;

    @Value("${albanero.unblock.request.email1}")
    private String unblockRequestEmail1;

    @Value("${albanero.unblock.request.email2}")
    private String unblockRequestEmail2;

    @Value("${albanero.account.approval.instance.base.email}")
    private String instanceBaseEmail;

    /**
     * Method to Send Verification Email
     *
     * @param request {@link  HttpServletRequest}
     * @param user  {@link  UserProfile}
     * @param org  {@link Organization}
     */
    public void sendVerificationEmail(HttpServletRequest request, UserProfile user, Organization org) {
        try {
        AccountStatus aStatus = accStatusRepo.findByUserId(user.getId());
        String toAddress = user.getEmailId();
        String fromAddress = PLATFORM_OPS.toString();
        String senderName = ALBANERO.toString();
        String subject = "Please verify your registration";
        String content = DEAR_NAME+ "Please click the link below to verify your registration on the Organization - " + org.getName() + ":<br>"
                + "<h3><a href=\"[[URL]]\" target=\"_self\">Click here to verify</a></h3>" + THANK_YOU.toString()
                + ALBANERO;

        content = content.replace(NAME.toString(), user.getFirstName() + " " + user.getLastName());
        String verifyURL = request.getHeader(HttpHeaders.ORIGIN) + "/auth-verify/user/api/user/verify/email/"
                + aStatus.getEmailStatus().getVerificationCode();

        content = content.replace("[[URL]]", verifyURL);

        sendEmail(toAddress, fromAddress, senderName, subject, content);
        } catch (MessagingException | UnsupportedEncodingException e) {
            LOGGER.info(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG,EMAIL_UTIL, "sendVerificationEmail","Error occurred while sending verification email", e.getStackTrace());
            throw new EmailUtilException(ACTIVATION_MAIL_EXCEPTION.label, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    /**
     * Method to send account approval mail to specific email
     *
     * @param toAddress {@link String}
     * @param user {@link UserProfile}
     * @param request {@link HttpServletRequest}
     * @param userEncodedEmail {@link String}
     * @param org {@link Organization}
     */
    public void sendEmailForApproval(String toAddress,UserProfile user, HttpServletRequest request ,
                                    String userEncodedEmail, Organization org)throws MessagingException, UnsupportedEncodingException {

        String fromAddress = PLATFORM_OPS.toString();
        String senderName = ALBANERO.toString();
        String subject = "Account Approval for Albanero Platform";


        String otpToken = requestUtil.verificationToken(toAddress, TokenConstants.APPROVE_EMAIL_TOKEN_DURATION);
        BasicTextEncryptor encryptor = new BasicTextEncryptor();
        encryptor.setPassword(encryptorPassword);
        String encryptedOtpToken = encryptor.encrypt(otpToken);
        String urlEncryptedOtpToken = URLEncoder.encode(encryptedOtpToken, StandardCharsets.UTF_8.toString());

        String content = DEAR_NAME.toString()
                + CHOOSE_BELOW_LINK.toString() + org.getName() + ": " + user.getEmailId()
                + "<br>" + APPROVE.toString()
                +DISAPPROVE.toString() + THANK_YOU.toString() + ALBANERO.toString();

        content = content.replace(NAME.toString(), ALBANERO_ADMIN.toString());
        String verifyURL = request.getHeader(HttpHeaders.ORIGIN) + VERIFY_URL
                + userEncodedEmail + "/" + urlEncryptedOtpToken;
        content = content.replace(YES.toString(), verifyURL + TRUE);
        content = content.replace(NO.toString(), verifyURL + FALSE);

        sendEmail(toAddress, fromAddress, senderName, subject, content);
    }
    /**
     * Method to send account approval email
     *
     * @param user {@link UserProfile}}
     */
    public void sendApprovalEmail(HttpServletRequest request, UserProfile user, Organization org) throws MessagingException, UnsupportedEncodingException {

        String userEncodedEmail = URLEncoder.encode(user.getEmailId(), StandardCharsets.UTF_8.toString());

        List<String> approverEmails = Arrays.asList(email1,email2,email3,email4,email4,email5,email6,email7,email8,email9);
        
        for(String email: approverEmails){
            UserProfile userProfile = userRepository.findByEmailId(email);
            if(!Objects.isNull(userProfile)){
                sendEmailForApproval(email, user, request, userEncodedEmail, org);
            }
        }

        String originName = request.getHeader(HttpHeaders.ORIGIN);
        if (originName != null && !originName.isEmpty()) {

            String albaneroInstanceEmail = getInstanceName(originName) + instanceBaseEmail;
            sendEmailForApproval(albaneroInstanceEmail, user, request, userEncodedEmail, org);
        }
    }

    /**
     * Method to send email for unblocking user
     *
     * @param request {@link HttpServletRequest}
     * @param user  {@link UserProfile}
     * @param ip  {@link String}
     */
    public void sendUnblockRequestMail(HttpServletRequest request, UserProfile user , String ip) throws MessagingException, UnsupportedEncodingException {
        String toAddress = unblockRequestEmail1;
        String fromAddress = PLATFORM_OPS.toString();
        String senderName = ALBANERO.toString();
        String subject = "Account Unblock Request for Albanero Platform";
        String content = DEAR_NAME.toString()
                + "Please choose the below links to unblock the given user account: " + user.getEmailId()
                + "<br>" + "<h3><a href=\"[[YES]]\" target=\"_self\">Unblock</a></h3>"
                + THANK_YOU.toString() + ALBANERO.toString();

        String otpToken = requestUtil.verificationToken(toAddress, TokenConstants.APPROVE_EMAIL_TOKEN_DURATION);
        BasicTextEncryptor encryptor = new BasicTextEncryptor();
        encryptor.setPassword(encryptorPassword);
        String encryptedOtpToken = encryptor.encrypt(otpToken);
        String urlEncryptedOtpToken = URLEncoder.encode(encryptedOtpToken, StandardCharsets.UTF_8.toString());
        String urlEncryptedIp = URLEncoder.encode(ip, StandardCharsets.UTF_8.toString());

        content = content.replace(NAME.toString(), ALBANERO_ADMIN.toString());
        String verifyURL = request.getHeader(HttpHeaders.ORIGIN) + "/auth-verify/user/api/user/unblock-account/"
                + user.getEmailId() + "/" + urlEncryptedIp + "/" + urlEncryptedOtpToken;

        content = content.replace(YES.toString(), verifyURL);

        sendEmail(toAddress, fromAddress, senderName, subject, content);

        toAddress = unblockRequestEmail2;
        sendEmail(toAddress, fromAddress, senderName, subject, content);
    }

    /**
     * Method to send OTP to user
     *
     * @param userProfile  {@link UserProfile}
     * @param passcode  {@link Integer}
     */
    public void sendOtpEmail(UserProfile userProfile, int passcode)
            throws MessagingException, UnsupportedEncodingException {

        String toAddress = userProfile.getEmailId();
        String fromAddress = "no.reply.albanero.platform@gmail.com";
        String senderName = ALBANERO.toString();
        String subject = "OTP for login";
        String content = DEAR_NAME.toString() + "You can use the following OTP for login : " + "<h3>" + passcode
                + "</h3>" + "<br><br><br>" + THANK_YOU.toString() + ALBANERO.toString();

        content = content.replace(NAME.toString(), userProfile.getFirstName() + " " + userProfile.getLastName());
        sendEmail(toAddress, fromAddress, senderName, subject, content);
    }

    /**
     * Method to send invitation to organization members to join organization.
     *
     * @param request  {@link HttpServletRequest}
     * @param admin  {@link String}
<<<<<<< HEAD
<<<<<<< HEAD
     * @param   {@link String}
=======
     * @param addMemberRequest  {@link com.albanero.authservice.common.dto.request.AddMembersRequest}
>>>>>>> 7ca746b (circular dependency resolved)
=======
     * @param addMemberRequest  {@link com.albanero.authservice.common.dto.request.AddMembersRequest}
>>>>>>> bugfix-KAB-161-platform-authentication-service
     * @param org  {@link Organization}
     */
    public void sendOrgInviteEmail(HttpServletRequest request, String admin, AddRemoveMemberRequest addMemberRequest, Organization org)
            throws MessagingException, UnsupportedEncodingException {
        String mail = addMemberRequest.getEmail();
		String fromAddress = PLATFORM_OPS.toString();
		String senderName = ALBANERO.toString();
		String subject = "Invitation to Organization : " + org.getName().toLowerCase();
		String content = DEAR_NAME.toString() + admin + " has invited you to join the " + org.getName().toLowerCase()
				+ " organization" + "<br>" + "<h2><a href=\"[[JOIN]]\" target=\"_self\">Click here to join</a></h2>"
                + "<h4>Please note that the above link is valid for the next 3 hours only.</h4>"
				+ THANK_YOU.toString() + ALBANERO.toString();

		content = content.replace(NAME.toString(), mail);
		
		String otpToken = requestUtil.verificationOtpToken(addMemberRequest, TokenConstants.ORG_PROJECT_MEMBER_INVITE_TOKEN_DURATION);
		BasicTextEncryptor encryptor = new BasicTextEncryptor();
		encryptor.setPassword(encryptorPassword);
		String encryptedOtpToken = encryptor.encrypt(otpToken);
		String urlEncryptedOtpToken = URLEncoder.encode(encryptedOtpToken, StandardCharsets.UTF_8.toString());

		String verifyURL = request.getHeader(HttpHeaders.ORIGIN) + "/auth-verify/organization/user/join/" + mail
				+ "/" + urlEncryptedOtpToken;

		content = content.replace("[[JOIN]]", verifyURL);

		sendEmail(mail, fromAddress, senderName, subject, content);

	}

    /**
     * Method to send invitation to project members to join Project.
     *
     * @param request  {@link HttpServletRequest}
     * @param admin  {@link String}
<<<<<<< HEAD
<<<<<<< HEAD
     * @param   {@link String}
=======
     * @param addMemberRequest  {@link com.albanero.authservice.common.dto.request.AddMembersRequest}
>>>>>>> 7ca746b (circular dependency resolved)
=======
     * @param addMemberRequest  {@link com.albanero.authservice.common.dto.request.AddMembersRequest}
>>>>>>> bugfix-KAB-161-platform-authentication-service
     * @param org  {@link Organization}
     **/
	public void sendProjectInviteEmail(HttpServletRequest request, String admin, AddRemoveMemberRequest addMemberRequest, Organization org,
			Project project) throws MessagingException, UnsupportedEncodingException {
        String mail = addMemberRequest.getEmail();
		String fromAddress = PLATFORM_OPS.toString();
		String senderName = ALBANERO.toString();
		String subject = "Invitation to " + org.getName().toLowerCase() + " project : "
				+ project.getName().toLowerCase();
		String content = DEAR_NAME.toString() + admin + " has invited you to join the project "
				+ project.getName().toLowerCase() + " of Organization : " + org.getName().toLowerCase()
				+ "<h3><a href=\"[[JOIN]]\" target=\"_self\">Click here to join</a></h3>"
                + "<h4>Please note that the above link is valid for the next 3 hours only.</h4>"
                + THANK_YOU.toString() + ALBANERO.toString();

		content = content.replace(NAME.toString(), mail);

        String otpToken = requestUtil.verificationOtpToken(addMemberRequest, TokenConstants.ORG_PROJECT_MEMBER_INVITE_TOKEN_DURATION);
		BasicTextEncryptor encryptor = new BasicTextEncryptor();
		encryptor.setPassword(encryptorPassword);
		String encryptedOtpToken = encryptor.encrypt(otpToken);
		String urlEncryptedOtpToken = URLEncoder.encode(encryptedOtpToken, StandardCharsets.UTF_8.toString());

		String verifyURL = request.getHeader(HttpHeaders.ORIGIN) + "/auth-verify/organization/project/user/join/"
				+ mail + "/" + urlEncryptedOtpToken;

		content = content.replace("[[JOIN]]", verifyURL);

		sendEmail(mail, fromAddress, senderName, subject, content);

	}

    /**
     * Method to send account approval email to user
     *
     * @param user
     * @throws MessagingException
     * @throws UnsupportedEncodingException
     */
    public void sendApprovedEmail(UserProfile user) throws MessagingException, UnsupportedEncodingException {
        String toAddress = user.getEmailId();
        String fromAddress = PLATFORM_OPS.toString();
        String senderName = ALBANERO.toString();
        String subject = "Your Albanero Account Has Been Approved";
        String content = "Dear User,<br>" + "Your Albanero account " + toAddress + " has been approved by the Admin.<br>Thank you,<br>Albanero";

        content = content.replace(NAME.toString(), user.getFirstName() + " " + user.getLastName());

        sendEmail(toAddress, fromAddress, senderName, subject, content);
    }

    /**
     * Method to send account approval mail to multiple users
     *
     * @param userEmail {@link ArrayList}
     * @param accountStatus  {@link Boolean}
     * @param statusChange  {@link String}
     */
	public void sendAccountStatusUpdateToMultipleUsers(List<String> userEmail, Boolean accountStatus, String statusChange)
			throws MessagingException, UnsupportedEncodingException {
		String fromAddress = PLATFORM_OPS.toString();
		String senderName = ALBANERO.toString();
		String subject = null;
		String content = null;
		if(Boolean.TRUE.equals(accountStatus)) {
            if (Objects.equals(statusChange, EmailConstants.APPROVED)) {
                subject = "Your Albanero Account Has Been Approved";
                content = "Dear User,<br> Your Albanero account has been approved by the Admin<br>Thank you,<br>Albanero";
            } else {
                subject = "Your Albanero Account Has Been Activated";
                content = "Dear User,<br> Your Albanero account has been activated by the Admin<br>Thank you,<br>Albanero";
            }

            sendEmailToMultipleUsers(userEmail, fromAddress, senderName, subject, content);
		}
	}

    /**
     * Method to send email to multiple users
     *
     * @param userEmail  {@link ArrayList}
     * @param fromAddress  {@link String}
     * @param senderName  {@link String}
     * @param subject  {@link String}
     * @param content  {@link String}
     */
    public void sendEmailToMultipleUsers(List<String> userEmail, String fromAddress, String senderName, String subject, String content)
            throws UnsupportedEncodingException, MessagingException {

        String[] userEmailArray = new String[userEmail.size()];
        userEmailArray = userEmail.toArray(userEmailArray);

        Properties properties = System.getProperties();
        properties.put(MAIL_SMTP_HOST, mailHost);
        properties.put(MAIL_SMTP_PORT, mailPort);
        properties.put(MAIL_SMTP_STARTTLS_ENABLE, mailEnable);
        properties.put(MAIL_SMTP_AUTH, mailAuth);

        Session session = Session.getInstance(properties, new Authenticator() {

            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(mailUsername, mailPassword);
            }
        });
        Transport transport = session.getTransport();
        transport.connect();

        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message);
        try {
            helper.setFrom(fromAddress, senderName);
            helper.setBcc(userEmailArray);
            helper.setSubject(subject);
            helper.setText(content, true);

            mailSender.send(message);
            transport.close();

        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, EMAIL_UTIL, "sendEmailToMultipleUsers", e.getMessage(), e.getStackTrace());
        }
    }

    public void sendMultipleEmails(List<String> userEmail, String fromAddress, String senderName, String subject, String content)
            throws UnsupportedEncodingException, MessagingException {
        MimeMessage[] messages = new MimeMessage[userEmail.size()];
        for (int i = 0; i < userEmail.size(); i++) {
            messages[i] = buildMessageForEmail(userEmail.get(i), fromAddress, senderName, subject, content);
        }

        sendMultipleEmailsInBatch(messages);
    }


    private MimeMessage buildMessageForEmail(String toAddress, String fromAddress, String senderName, String subject, String content) throws MessagingException, UnsupportedEncodingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message);

        helper.setFrom(fromAddress, senderName);
        helper.setTo(toAddress);
        helper.setSubject(subject);
        helper.setText(content, true);

        return message;
    }

    /**
     * method to send email for resetting MfaQr
     *
     * @param user {@link UserProfile}
     * @param qrLink  {@link String}
     * @param secretKey  {@link String}
     */
    public void sendResetMfaQrEmail(UserProfile user, String qrLink, String secretKey) {
       try {
           String toAddress = user.getEmailId();
           String fromAddress = PLATFORM_OPS.toString();
           String senderName = ALBANERO.toString();
           String subject = "Reset MFA QR link";
           String content = DEAR_NAME.toString() + "Please find the QR link to reset MFA through Google Authenticator Application " + qrLink + ".<br>In case you are facing any issue with QR, please try adding this setup key " + secretKey + ".<br>Thank you,<br>Albanero";

           content = content.replace(NAME.toString(), user.getFirstName() + " " + user.getLastName());

           sendEmail(toAddress, fromAddress, senderName, subject, content);
       }   catch (MessagingException | UnsupportedEncodingException e) {
           LOGGER.info(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, EMAIL_UTIL, "sendResetMfaQrEmail", "Error occurred while sending Reset MFA QR email", e.getStackTrace());
           throw new EmailUtilException(MFA_RESET_QR_MAIL_EXCEPTION.label,HttpStatus.INTERNAL_SERVER_ERROR);
       }
    }

    /**
     * Method to send email to user
     *
     * @param toAddress  {@link String}
     * @param fromAddress  {@link String}
     * @param senderName  {@link String}
     * @param subject  {@link String}
     * @param content  {@link String}
     */
    public void sendEmail(String toAddress, String fromAddress, String senderName, String subject, String content)
            throws UnsupportedEncodingException, MessagingException {

        Properties properties = System.getProperties();
        properties.put(MAIL_SMTP_HOST, mailHost);
        properties.put(MAIL_SMTP_PORT, mailPort);
        properties.put(MAIL_SMTP_STARTTLS_ENABLE, mailEnable);
        properties.put(MAIL_SMTP_AUTH, mailAuth);

        Session session = Session.getInstance(properties, new Authenticator() {

            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(mailUsername, mailPassword);
            }
        });
        Transport transport = session.getTransport();
        transport.connect();

        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message);
        try {
            helper.setFrom(fromAddress, senderName);
            helper.setTo(toAddress);
            helper.setSubject(subject);
            helper.setText(content, true);

            mailSender.send(message);
            transport.close();

        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, EMAIL_UTIL, "sendEmail", e.getMessage(), e.getStackTrace());
        }
    }

    private void sendMultipleEmailsInBatch(MimeMessage[] messages) throws MessagingException {

        Properties properties = System.getProperties();
        properties.put(MAIL_SMTP_HOST, mailHost);
        properties.put(MAIL_SMTP_PORT, mailPort);
        properties.put(MAIL_SMTP_STARTTLS_ENABLE, mailEnable);
        properties.put(MAIL_SMTP_AUTH, mailAuth);

        Session session = Session.getInstance(properties, new Authenticator() {

            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(mailUsername, mailPassword);
            }
        });
        Transport transport = session.getTransport();
        transport.connect();
        log.info("Triggering {} emails at once", messages.length);
        mailSender.send(messages);

        transport.close();
        log.info("{} emails are sent at once", messages.length);
    }

    public String getInstanceName(String originName){
        String orgUrl = originName.substring(8);
        return orgUrl.split("\\.")[0];
    }

    public BaseResponse generateQrAndSentToUser (RegistrationUser user, UserProfile userProfile, MfaStatus
            mfaStatus, HttpServletRequest request){

        BaseResponse baseResponse = new BaseResponse();
        RegisterUserResponse registerUserResponse = new RegisterUserResponse();

        String secret = requestUtil.generateMFASecret();

        String userMail = user.getMailId() != null ? user.getMailId() : userProfile.getEmailId();

        String albaneroInstance = getAlbaneroInstance(request);
        String qr = generateQRUrl(userMail, secret, albaneroInstance);
        if (user.getIsResetMfaRequest() != null && user.getIsResetMfaRequest()) {
            Mfa mfa = new Mfa();
            mfa.setMfaSecret(secret);
            mfa.setProviderApp(MfaConstants.PROVIDERAPP);
            mfaStatus.setIsEnabled(true);
            mfaStatus.setMfa(mfa);

            mfaRepo.save(mfaStatus);
            sendResetMfaQrEmail(userProfile, qr, secret);
            baseResponse.setMessage("QR image had been regenerated successfully and sent to your email!");
            baseResponse.setSuccess(true);
        } else {
            registerUserResponse.setSecret(secret);
            registerUserResponse.setSecretQrImageUri(qr);
            baseResponse.setPayload(registerUserResponse);
            baseResponse.setMessage("QR image and MFA secret returned!");
            baseResponse.setSuccess(true);
        }
        return baseResponse;
    }

    public String getAlbaneroInstance(HttpServletRequest request) {

        String albaneroInstance = MfaConstants.ALBANERO_PLATFORM;

        String originName = request.getHeader(HttpHeaders.ORIGIN);
        if (originName != null && !originName.isEmpty()) {
            String orgUrl = originName.substring(8);
            String instanceName = orgUrl.split("\\.")[0];
            instanceName = instanceName.substring(0, 1).toUpperCase() + instanceName.substring(1);

            albaneroInstance = "Albanero " + instanceName + " Platform";
        }
        return albaneroInstance;
    }

    /**
     * Method to generate QR link for MFA registration
     *
     * @param email  {@link String}
     *  @param secret  {@link String}
     */

    public static String generateQRUrl(String email, String secret , String albaneroInstance) {
        return MfaConstants.QR_PREFIX + URLEncoder.encode(String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s",
                albaneroInstance, email, secret, albaneroInstance), StandardCharsets.UTF_8);
    }

}
