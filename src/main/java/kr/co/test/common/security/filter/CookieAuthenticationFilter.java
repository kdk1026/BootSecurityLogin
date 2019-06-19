package kr.co.test.common.security.filter;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

/**
 * <pre>
 * 개정이력
 * -----------------------------------
 * 2019. 4. 15. 김대광	최초작성
 * </pre>
 * 
 *
 * @author 김대광
 */
public class CookieAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	// https://stackoverflow.com/questions/38341114/spring-security-cookie-jwt-authentication
	
	private String usernameParameter = "";
	private String passwordParameter = ""; 
	
	public CookieAuthenticationFilter(String defaultFilterProcessesUrl, String usernameParameter, String passwordParameter) {
		super(defaultFilterProcessesUrl);
		
		this.usernameParameter = usernameParameter;
		this.passwordParameter = passwordParameter;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		// TODO Auto-generated method stub
		return null;
	}

}
