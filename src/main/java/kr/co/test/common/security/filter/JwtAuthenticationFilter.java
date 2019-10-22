package kr.co.test.common.security.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import common.ResponseCodeEnum;
import common.util.json.JacksonUtil;
import kr.co.test.common.security.web.model.AuthenticatedUser;
import kr.co.test.model.ResultVo;
import kr.co.test.service.jwt.JwtTokenProvider;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private JwtTokenProvider jwtTokenProvider;

	public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider) {
		this.jwtTokenProvider = jwtTokenProvider;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		ResultVo result = new ResultVo();


		// 1. 헤더에서 토큰 가져오기
		String sToken = jwtTokenProvider.getTokenFromReqHeader(request);

		if ( StringUtils.isEmpty(sToken) ) {
			result.setRes_cd(ResponseCodeEnum.ACCESS_TOEKN_INVALID.getCode());
			result.setRes_msg(ResponseCodeEnum.ACCESS_TOEKN_INVALID.getMessage());
		} else {
			AuthenticatedUser authUser = null;

			// 2. 토큰 유효성 검증
			switch ( jwtTokenProvider.isValidateJwtToken(sToken) ) {
			case 0:
				result.setRes_cd(ResponseCodeEnum.ACCESS_TOEKN_INVALID.getCode());
				result.setRes_msg(ResponseCodeEnum.ACCESS_TOEKN_INVALID.getMessage());
				break;
			case 2:
				result.setRes_cd(ResponseCodeEnum.ACCESS_TOKEN_EXPIRED.getCode());
				result.setRes_msg(ResponseCodeEnum.ACCESS_TOKEN_EXPIRED.getMessage());
				break;

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
			String sMessage = JacksonUtil.converterObjToJsonStr(result);

			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			response.setCharacterEncoding(StandardCharsets.UTF_8.toString());
			response.getWriter().write(sMessage);
		} else {
			filterChain.doFilter(request, response);
		}
	}

}
