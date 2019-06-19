package kr.co.test.common.security.handler;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import common.ResponseCodeEnum;
import common.util.ResponseUtil;
import common.util.json.GsonUtil;
import kr.co.test.common.Constants;

/**
 * <pre>
 * 개정이력
 * -----------------------------------
 * 2019. 4. 6. 김대광	최초작성
 * </pre>
 * 
 *
 * @author 김대광
 */
public class RestAccessDeniedHandler implements AccessDeniedHandler {

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException, ServletException {

		Map<String, Object> retMap = new HashMap<>();
		retMap.put(Constants.RES.RES_CD, 	ResponseCodeEnum.ACCESS_DENIED.getCode());
		retMap.put(Constants.RES.RES_MSG, 	ResponseCodeEnum.ACCESS_DENIED.getMessage());
		
		String sMessage = GsonUtil.ToJson.converterMapToJsonStr(retMap);
		
		response.setStatus(HttpServletResponse.SC_FORBIDDEN);
		
		ResponseUtil.setJsonResponse(response, sMessage);
	}
	
}
