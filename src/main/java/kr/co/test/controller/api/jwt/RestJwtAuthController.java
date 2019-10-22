package kr.co.test.controller.api.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import common.LogDeclare;
import common.util.map.ResultSetMap;
import kr.co.test.config.mvc.resolver.ParamCollector;
import kr.co.test.service.jwt.JwtAuthService;

@RestController
@RequestMapping("/api/jwt/login")
public class RestJwtAuthController extends LogDeclare {

	@Autowired
	private JwtAuthService jwtAuthService;

	@RequestMapping("/auth")
	public ResultSetMap auth(ParamCollector paramCollector) {
		return jwtAuthService.processAuthByUsername(paramCollector);
	}

	@RequestMapping("/refresh")
	public ResultSetMap refresh(ParamCollector paramCollector) {
		return jwtAuthService.processRefresh(paramCollector);
	}

}
