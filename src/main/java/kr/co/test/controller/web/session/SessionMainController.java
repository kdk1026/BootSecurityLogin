package kr.co.test.controller.web.session;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import kr.co.test.config.mvc.resolver.ParamCollector;
import kr.co.test.service.session.SessionLoginService;

/**
 * @since 2018. 12. 24.
 * @author 김대광
 * <pre>
 * -----------------------------------
 * 개정이력
 * 2018. 12. 24. 김대광	최초작성
 * </pre>
 */
@RestController
@RequestMapping("session")
public class SessionMainController {
	
	@Autowired
	SessionLoginService sessionLoginService;

	@GetMapping("/main")
	public ModelAndView login(ParamCollector paramCollector) {
		ModelAndView mav = new ModelAndView();
		
		mav.addObject("expires_in", sessionLoginService.getSessionExpireSecond());
		mav.addObject("logoutUri", sessionLoginService.getLogoutUri());
		
		mav.setViewName("session/main");
		return mav;
	}
	
}
