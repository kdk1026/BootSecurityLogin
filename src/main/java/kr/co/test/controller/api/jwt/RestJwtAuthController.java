package kr.co.test.controller.api.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import common.LogDeclare;
import common.util.map.ParamMap;
import common.util.map.ResultSetMap;
import kr.co.test.config.mvc.resolver.ParamCollector;
import kr.co.test.service.jwt.RestJwtAuthService;
import kr.co.test.service.session.RestSessionConfirmService;

/**
 * <pre>
 * 개정이력
 * -----------------------------------
 * 2019. 10. 22. 김대광	최초작성
 * </pre>
 *
 *
 * @author 김대광
 */
@RestController
@RequestMapping("/api/jwt/login")
public class RestJwtAuthController extends LogDeclare {

	@Autowired
	private RestJwtAuthService jwtAuthService;

	@Autowired
	private RestSessionConfirmService restSessionConfirmService;

	@RequestMapping("/auth")
	public ResultSetMap auth(ParamCollector paramCollector) {
		return jwtAuthService.processAuthByUsername(paramCollector);
	}

	@RequestMapping("/refresh")
	public ResultSetMap refresh(ParamCollector paramCollector) {
		return jwtAuthService.processRefresh(paramCollector);
	}

	@PostMapping("/confirm")
	public ParamMap confirm(ParamCollector paramCollector) {
		return restSessionConfirmService.processConfirm(paramCollector);
	}

}
