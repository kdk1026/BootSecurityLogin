package kr.co.test.common.security;

import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import common.LogDeclare;
import kr.co.test.common.security.web.model.AuthenticatedUser;
import kr.co.test.common.security.web.service.UserService;

/**
 * <pre>
 * 개정이력
 * -----------------------------------
 * 2019. 3. 27. 김대광	최초작성
 * </pre>
 * 
 *
 * @author 김대광
 */
@Component
public class UserAuthenticationProvider extends LogDeclare implements AuthenticationProvider {
	
	@Autowired
	UserService userService;

	@Autowired
	BCryptPasswordEncoder passwordEncoder;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        AuthenticatedUser user = null;
        Collection<GrantedAuthority> authorities = null;
        
    	user = (AuthenticatedUser) userService.loadUserByUsername(username);
    	
    	if (user != null) {
    		if ( !passwordEncoder.matches(password, user.getPassword()) ) {
    			throw new BadCredentialsException("비밀번호 불일치");
    		}
    		
    		authorities = user.getAuthorities();
    		return new UsernamePasswordAuthenticationToken(user, password, authorities);
    	} else {
    		return null;
    	}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}
	
}
