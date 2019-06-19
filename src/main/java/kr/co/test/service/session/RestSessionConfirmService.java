package kr.co.test.service.session;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import common.util.map.ParamMap;
import kr.co.test.common.security.web.model.AuthenticatedUser;
import kr.co.test.config.mvc.resolver.ParamCollector;

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
@Service
public class RestSessionConfirmService {

	public ParamMap processConfirm(ParamCollector paramCollector) {
		ParamMap retMap = new ParamMap();
		
		Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		AuthenticatedUser user = (AuthenticatedUser) principal;
		
		retMap.put("id", 				user.getId());
		retMap.put("name", 				user.getName());
		retMap.put("last_login_dt", 	user.getLast_login_dt());
		retMap.put("last_pwd_upd_dt", 	user.getLast_pwd_upd_dt());
		
		return retMap;
	}
	
}
