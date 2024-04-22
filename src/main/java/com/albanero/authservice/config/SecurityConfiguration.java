package com.albanero.authservice.config;

import com.albanero.authservice.common.constants.AllowedEndpoints;
import com.albanero.authservice.filter.AuthenticationFilter;
import com.albanero.authservice.filter.JwtAuthenticationEntryPoint;
import com.albanero.authservice.service.impl.AuthServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Properties;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfiguration {

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

	private final AuthServiceImpl authService;

    private  final PasswordEncoder passwordEncoder;

	private final AuthenticationFilter authenticationFilter;

	private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

	@Autowired
	public SecurityConfiguration(AuthServiceImpl authService, AuthenticationFilter authenticationFilter,
                                 JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint, PasswordEncoder passwordEncoder) {
		this.authService = authService;
		this.authenticationFilter = authenticationFilter;
		this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.passwordEncoder = passwordEncoder;
	}


    @Bean
    public JavaMailSender javaMailSender() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost(mailHost);
        mailSender.setPort(mailPort);

        mailSender.setUsername(mailUsername);
        mailSender.setPassword(mailPassword);

        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", mailAuth);
        props.put("mail.smtp.starttls.enable", mailEnable);
        props.put("mail.debug", "true");

        return mailSender;
    }

    @Bean
    @Primary
    public AuthenticationManager authenticationManagerBean(){
        return new AuthManager(passwordEncoder, authService);
    }

    @Bean
    public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
        return new PropertySourcesPlaceholderConfigurer();
    }

    /**
     * method that provides customization for permitted end-points
     *
     * @param http {@link HttpSecurity}
     */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorizer -> authorizer.requestMatchers(AllowedEndpoints.getAllowedEndPoints()).permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(handler -> handler.authenticationEntryPoint(jwtAuthenticationEntryPoint))
                .sessionManagement(httpSecuritySessionManagementConfigurer ->
                        httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class)
        ;

        return http.build();
    }

}
