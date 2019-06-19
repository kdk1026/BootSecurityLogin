package kr.co.test.securityBcrypt;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * <pre>
 * 개정이력
 * -----------------------------------
 * 2019. 4. 9. 김대광	최초작성
 * </pre>
 * 
 *
 * @author 김대광
 */
public class SecurityBCryptTest {

	private static final Logger logger = LoggerFactory.getLogger(SecurityBCryptTest.class);
	
	@Test
	public void test() {
		String password = "admin!@34";
		
		BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		String passwordHashed = passwordEncoder.encode(password);
		
		logger.debug("bcrypt: {}", passwordHashed);
		logger.debug("valid: {}", passwordEncoder.matches(password, passwordHashed));		
	}
	
	
}
