package kr.co.test.controller.web.jwt;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import common.LogDeclare;
import common.ResponseCodeEnum;
import kr.co.test.config.mvc.resolver.ParamCollector;
import kr.co.test.model.ResultVo;
import kr.co.test.service.jwt.JwtLoginService;

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
@RequestMapping("jwt")
public class JwtLoginController extends LogDeclare {

	@Autowired
	private JwtLoginService jwtLoginService;

	@RequestMapping(value = "/login", method = {RequestMethod.GET, RequestMethod.POST})
	public ModelAndView login(ParamCollector paramCollector) {
		ModelAndView mav = new ModelAndView();
		mav.setViewName("jwt/login");

		return mav;
	}

	@PostMapping("/login/auth")
	public ModelAndView loginAuth(ParamCollector paramCollector, RedirectAttributes attributes, HttpServletResponse response) throws Exception {
		ModelAndView mav = new ModelAndView();
		String sRedirectUrl = "";

		ResultVo resultVo = jwtLoginService.processLogin(paramCollector, response);

		if ( ResponseCodeEnum.SUCCESS.getCode().equals(resultVo.getRes_cd()) ) {
			sRedirectUrl = "redirect:/jwt/main";
		} else {
			sRedirectUrl = "redirect:/jwt/login";

			attributes.addFlashAttribute("res_msg", resultVo.getRes_msg());
		}

		mav.setViewName(sRedirectUrl);
		return mav;
	}

	@RequestMapping(value = "/logout", method = {RequestMethod.GET, RequestMethod.POST})
	public ModelAndView logout(ParamCollector paramCollector, HttpServletResponse response) {
		ModelAndView mav = new ModelAndView();

		jwtLoginService.processLogout(response);

		mav.setViewName("redirect:/jwt/login");
		return mav;
	}

}
