package kr.co.test.controller.web.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import kr.co.test.config.mvc.resolver.ParamCollector;
import kr.co.test.service.jwt.JwtLoginService;

/**
 * <pre>
 * -----------------------------------
 * 개정이력
 * 2019. 10. 22. 김대광	최초작성
 * </pre>
 */
@RestController
@RequestMapping("jwt")
public class JwtMainController {

	@Autowired
	private JwtLoginService jwtLoginService;

	@GetMapping("/main")
	public ModelAndView login(ParamCollector paramCollector) {
		ModelAndView mav = new ModelAndView();

		mav.addObject("expires_in", jwtLoginService.getSessionExpireSecond());
		mav.addObject("logoutUri", jwtLoginService.getLogoutUri());

		mav.setViewName("jwt/main");
		return mav;
	}

}
