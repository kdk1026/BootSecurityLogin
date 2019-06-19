package kr.co.test.common.security.handler;

import java.io.IOException;
import java.util.Date;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import common.ResponseCodeEnum;
import common.util.ResponseUtil;
import common.util.date.Jsr310DateUtil;
import common.util.json.GsonUtil;
import common.util.map.MapUtil;
import common.util.map.ParamMap;
import kr.co.test.model.ResultVo;

/**
 * <pre>
 * 개정이력
 * -----------------------------------
 * 2019. 4. 14. 김대광	최초작성
 * </pre>
 * 
 *
 * @author 김대광
 */
public class RestSessionLoginSuccessHandler implements AuthenticationSuccessHandler {

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		
		ResultVo resultVo = new ResultVo();
		resultVo.setRes_cd(ResponseCodeEnum.SUCCESS.getCode());
    	resultVo.setRes_msg(ResponseCodeEnum.SUCCESS.getMessage());
    	
    	Map<String, String> map = MapUtil.objectToMap(resultVo);
    	
    	ParamMap retMap = new ParamMap();
		retMap.putAll(map);
		
		getSessionOptionInfo(request, authentication, retMap);
		
		String sRetJson = GsonUtil.ToJson.converterMapToJsonStr(retMap);
		ResponseUtil.setJsonResponse(response, sRetJson);
	}
	
	/**
	 * <pre>
	 * 세션 부가 정보
	 *  - API 전용
	 * </pre>
	 * @param request
	 * @param authentication
	 * @param retMap
	 */
	private void getSessionOptionInfo(HttpServletRequest request, Authentication authentication, ParamMap retMap) {
		@SuppressWarnings("unused")
		WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();
		HttpSession session = request.getSession();
		
		// XXX : 1번째 요청 시, 응답에 session_id 항목이 없고, 2번째 요청 이후부터 항목이 노출
//		retMap.put("session_id", 				details.getSessionId());
		
		retMap.put("session_id", 				session.getId());
		retMap.put("session_create_time", 		Jsr310DateUtil.Convert.getDateToString(new Date(session.getCreationTime()), "yyyyMMddHHmmss"));
		retMap.put("session_active_interval",	session.getMaxInactiveInterval());
	}
	
}
