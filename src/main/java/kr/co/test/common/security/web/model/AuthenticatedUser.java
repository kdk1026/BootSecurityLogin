package kr.co.test.common.security.web.model;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

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
@Getter
@Setter
@ToString(exclude = "pw")
public class AuthenticatedUser implements UserDetails {

	private static final long serialVersionUID = 1L;

	private String id; 
	private String pw;
	private Collection<GrantedAuthority> authorities;
	
	private int lock;
	
	private String name;
	private String last_login_dt;
	private String last_pwd_upd_dt;
	
	@Override
	public String getPassword() {
		return pw;
	}
	@Override
	public String getUsername() {
		return id;
	}
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}
	@Override
	public boolean isAccountNonLocked() {
		return (lock == 0) ? false : true;
	}
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}
	@Override
	public boolean isEnabled() {
		return true;
	}
	
}
