package kr.co.test.controller.web.cookie;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import common.LogDeclare;
import kr.co.test.config.mvc.resolver.ParamCollector;
import kr.co.test.service.cookie.CookieLoginService;

/**
 * <pre>
 * -----------------------------------
 * 개정이력
 * 2019. 10. 23. 김대광	최초작성
 * </pre>
 */
@RestController
@RequestMapping("cookie")
public class CookieMainController extends LogDeclare {

	@Autowired
	private CookieLoginService cookieLoginService;

	@GetMapping("/main")
	public ModelAndView login(ParamCollector paramCollector) {
		ModelAndView mav = new ModelAndView();

		mav.addObject("expires_in", cookieLoginService.getSessionExpireSecond());
		mav.addObject("logoutUri", cookieLoginService.getLogoutUri());

		mav.setViewName("cookie/main");
		return mav;
	}

}
