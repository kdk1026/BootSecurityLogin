package kr.co.test.common.security.web.service;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * <pre>
 * 개정이력
 * -----------------------------------
 * 2019. 3. 30. 김대광	최초작성
 * </pre>
 * 
 *
 * @author 김대광
 */
public interface UserService extends UserDetailsService {

	Collection<GrantedAuthority> getAuthorities(String username);
	
}
