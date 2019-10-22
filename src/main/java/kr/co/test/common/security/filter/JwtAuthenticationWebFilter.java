package kr.co.test.common.security.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import common.util.sessioncookie.CookieUtilVer2;
import kr.co.test.common.Constants;
import kr.co.test.common.security.web.model.AuthenticatedUser;
import kr.co.test.model.ResultVo;
import kr.co.test.service.jwt.JwtTokenProvider;

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
public class JwtAuthenticationWebFilter extends OncePerRequestFilter {

	private JwtTokenProvider jwtTokenProvider;

	public JwtAuthenticationWebFilter(JwtTokenProvider jwtTokenProvider) {
		this.jwtTokenProvider = jwtTokenProvider;
	}

	private static final String LOGIN_PAGE = "/jwt/login";

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		ResultVo result = new ResultVo();


		// 1. 쿠키에서 토큰 가져오기
		String sToken = CookieUtilVer2.getCookieValue(request, Constants.Jwt.ACCESS_TOKEN);

		if ( StringUtils.isEmpty(sToken) ) {
			response.sendRedirect(LOGIN_PAGE);
			return;

		} else {
			AuthenticatedUser authUser = null;

			// 2. 토큰 유효성 검증
			switch ( jwtTokenProvider.isValidateJwtToken(sToken) ) {
			case 0:
				response.sendRedirect(LOGIN_PAGE);
				return;
			case 2:
				response.sendRedirect(LOGIN_PAGE);
				return;

			default:
				break;
			}

			if ( StringUtils.isEmpty(result.getRes_cd()) ) {
				// 3. 토큰에서 로그인 정보 추출
				authUser = jwtTokenProvider.getAuthUserFromJwt(sToken);

				UsernamePasswordAuthenticationToken authentication
					= new UsernamePasswordAuthenticationToken(authUser, null, authUser.getAuthorities());

				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		}

		if ( !StringUtils.isEmpty(result.getRes_cd()) ) {
			response.sendRedirect(LOGIN_PAGE);
			return;
		} else {
			filterChain.doFilter(request, response);
		}
	}

}

