package kr.co.test.common.security.web.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;

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
@Mapper
public interface UserMapper {

	public AuthenticatedUser selectUser(String username);
	
	public List<String> selecttAuthorities(String username);
	
}
