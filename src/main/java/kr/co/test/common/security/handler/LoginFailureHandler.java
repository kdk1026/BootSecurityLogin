package kr.co.test.common.security.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import common.ResponseCodeEnum;

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
public class LoginFailureHandler implements AuthenticationFailureHandler {

	private String defaultFailureUrl;
	
	public LoginFailureHandler(String defaultFailureUrl) {
		this.defaultFailureUrl = defaultFailureUrl;
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {

		String sErrorMsg = "";
		
		if ( exception instanceof ProviderNotFoundException || exception instanceof BadCredentialsException ) {
			sErrorMsg = ResponseCodeEnum.LOGIN_INVALID.getMessage();
		} else {
			sErrorMsg = exception.getMessage();
		}
		
		request.setAttribute("res_msg", sErrorMsg);
		
		request.getRequestDispatcher(defaultFailureUrl).forward(request, response);
	}

}
