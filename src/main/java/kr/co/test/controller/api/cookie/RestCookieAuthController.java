package kr.co.test.controller.api.cookie;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import common.LogDeclare;
import common.util.map.ParamMap;
import kr.co.test.config.mvc.resolver.ParamCollector;
import kr.co.test.model.ResultVo;
import kr.co.test.service.cookie.CookieLoginService;
import kr.co.test.service.session.RestSessionConfirmService;

/**
 * <pre>
 * 개정이력
 * -----------------------------------
 * 2019. 10. 23. 김대광	최초작성
 * </pre>
 *
 *
 * @author 김대광
 */
@RestController
@RequestMapping("/api/cookie/login")
public class RestCookieAuthController extends LogDeclare {

	@Autowired
	private CookieLoginService cookieLoginService;

	@RequestMapping("/auth")
	public ResultVo auth(ParamCollector paramCollector, HttpServletResponse response) throws Exception {
		return cookieLoginService.processLogin(paramCollector, response);
	}

	@Autowired
	private RestSessionConfirmService restSessionConfirmService;

	@PostMapping("/confirm")
	public ParamMap confirm(ParamCollector paramCollector) {
		return restSessionConfirmService.processConfirm(paramCollector);
	}

}
