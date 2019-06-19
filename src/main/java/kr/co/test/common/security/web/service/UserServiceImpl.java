package kr.co.test.common.security.web.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import kr.co.test.common.security.web.mapper.UserMapper;
import kr.co.test.common.security.web.model.AuthenticatedUser;

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
@Service
public class UserServiceImpl implements UserService {
	
	@Autowired
	private UserMapper userMapper;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		AuthenticatedUser user = userMapper.selectUser(username);
		
		if (user != null) {
			user.setAuthorities(this.getAuthorities(username));
		}
		
		return user;
	}

	@Override
	public Collection<GrantedAuthority> getAuthorities(String username) {
		List<GrantedAuthority> listAuthority = null;
		
		List<String> listStrAuthority = userMapper.selecttAuthorities(username);
		
		if ( !listStrAuthority.isEmpty() ) {
			listAuthority = new ArrayList<GrantedAuthority>();
			
			for (String role : listStrAuthority) {
				listAuthority.add(new SimpleGrantedAuthority(role));
			}
		}

		return listAuthority;
	}
	
}
