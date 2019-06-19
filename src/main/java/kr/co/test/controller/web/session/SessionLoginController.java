package kr.co.test.controller.web.session;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import common.LogDeclare;
import kr.co.test.config.mvc.resolver.ParamCollector;

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
public class SessionLoginController extends LogDeclare {
	
	@RequestMapping(value = "/login", method = {RequestMethod.GET, RequestMethod.POST})
	public ModelAndView login(ParamCollector paramCollector) {
		ModelAndView mav = new ModelAndView();
		mav.setViewName("session/login");
		
		return mav;
	}
	
}
