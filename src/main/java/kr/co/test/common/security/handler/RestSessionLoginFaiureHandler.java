package kr.co.test.common.security.handler;

import java.io.IOException;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import common.ResponseCodeEnum;
import common.util.ResponseUtil;
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
public class RestSessionLoginFaiureHandler implements AuthenticationFailureHandler {

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {

		String sErrorMsg = "";
		
		if ( exception instanceof ProviderNotFoundException || exception instanceof BadCredentialsException ) {
			sErrorMsg = ResponseCodeEnum.LOGIN_INVALID.getMessage();
		} else {
			sErrorMsg = exception.getMessage();
		}
		
		ResultVo resultVo = new ResultVo();
		resultVo.setRes_cd(ResponseCodeEnum.LOGIN_INVALID.getCode());
    	resultVo.setRes_msg(sErrorMsg);
    	
    	Map<String, String> map = MapUtil.objectToMap(resultVo);
    	
    	ParamMap retMap = new ParamMap();
		retMap.putAll(map);
		
		String sRetJson = GsonUtil.ToJson.converterMapToJsonStr(retMap);
		ResponseUtil.setJsonResponse(response, sRetJson);
	}
	
}
