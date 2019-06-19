package kr.co.test.service.session;

import java.util.Properties;

import org.springframework.stereotype.Service;

import common.util.properties.PropertiesUtil;
import kr.co.test.common.mvc.service.CommonService;

/**
 * <pre>
 * 개정이력
 * -----------------------------------
 * 2019. 4. 1. 김대광	최초작성
 * </pre>
 * 
 *
 * @author 김대광
 */
@Service
public class SessionLoginService extends CommonService {

	/**
	 * 자동 로그아웃 처리를 위한 만료시간 가져오기
	 * @return
	 */
	public int getSessionExpireSecond() {
		int nExpireSecond = 0;
		
		try {
			Properties prop = PropertiesUtil.getPropertiesClasspath("common.properties");
			
			String sSessionExpireSecond = prop.getProperty("session.expire.second");
			nExpireSecond = Integer.parseInt(sSessionExpireSecond);
			
		} catch (Exception e) {
			logger.error("", e);
		}
		
		return nExpireSecond;
	}
	
	/**
	 * <pre>
	 * Spring 4 이후부터는 Security logout도 post만 가능
	 * Thymeleaf 에서 변수 생성 후, 전달 방법 모르므로...
	 * </pre>
	 * @return
	 */
	public String getLogoutUri() {
		return "/session/logout";
	}
	
}
