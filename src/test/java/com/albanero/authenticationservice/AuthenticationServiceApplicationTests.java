//package com.albanero.authenticationservice;
//
//import static org.junit.Assert.assertEquals;
//import static org.junit.Assert.assertNull;
//
//import java.net.URI;
//import java.net.URISyntaxException;
//
//import org.junit.jupiter.api.Test;
//import org.junit.runner.RunWith;
//import org.springframework.boot.test.context.SpringBootTest;
//import org.springframework.test.context.junit4.SpringRunner;
//import org.springframework.vault.authentication.TokenAuthentication;
//import org.springframework.vault.client.VaultEndpoint;
//import org.springframework.vault.core.VaultTemplate;
//import org.springframework.vault.support.VaultResponse;
//import org.springframework.vault.support.VaultResponseSupport;
//
//import com.albanero.authservice.component.Credentials;
//
//import lombok.AllArgsConstructor;
//import lombok.Data;
//
//@RunWith(SpringRunner.class)
//@SpringBootTest
//class AuthenticationServiceApplicationTests {
//
//	@Test
//	void contextLoads() {
//	}
//
//	@Test
//	public void vaultTest() throws URISyntaxException {
//		VaultTemplate vaultTemplate =  new VaultTemplate(VaultEndpoint.from(new URI("http://127.0.0.1:8200")), new TokenAuthentication("s.PNBUAfgoBYwzpuBNNofWFtJi"));
//        VaultResponse response = vaultTemplate.write("secret/authentication-service", new Credentials("mySecretKey"));
//        
//        assertNull(response);
//        VaultResponseSupport<Credentials> resp = vaultTemplate.read("secret/authentication-service", Credentials.class);
//        assertEquals("mySecretKey", resp.getData().getKey());
//        
//        System.out.println(resp);
//	}
//	
//	@Data
//	@AllArgsConstructor
//	//@ConfigurationProperties()
//	public class Credentials {
//		private String key;
//	}
//}
