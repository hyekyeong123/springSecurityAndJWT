package com.sp.fc.web.config;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.sp.fc.user.domain.SpUser;
import com.sp.fc.user.service.SpUserService;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.security.sasl.AuthenticationException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 리퀘스트가 올때 토큰을 검사하여 SecurityContextHolder에 Aythentication을 올려주는 역할을 한다.
// BasicAuthenticationFilter는 모든 요청에서 토큰을 검사한다.
public class JWTCheckFilter extends BasicAuthenticationFilter {

    private SpUserService userService;

    public JWTCheckFilter(AuthenticationManager authenticationManager, SpUserService userService) {
        super(authenticationManager);
        this.userService = userService;
    }

//  **************************************************************************

    // 사용자가 요청을 보낼때마다 토큰에 대한 검사를 하는 메서드
    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain
    ) throws IOException, ServletException {

        String bearer = request.getHeader(HttpHeaders.AUTHORIZATION);

        // 만약에 bearer 토큰이 없다면 요청을 흘려보내서 다음 필터 혹은 인터셉터에서 인증을 받게 한다.
        if(bearer == null || !bearer.startsWith("Bearer ")){
            chain.doFilter(request, response);
            return;
        }

        // bearer 토큰이 있다면
        String token = bearer.substring("Bearer ".length());

        // 토큰 검사
        VerifyResult result = JWTUtil.verify(token);

        if(result.isSuccess()){
            SpUser user = (SpUser) userService.loadUserByUsername(result.getUsername());

            UsernamePasswordAuthenticationToken userToken = new UsernamePasswordAuthenticationToken(
                    user.getUsername(), null, user.getAuthorities()
            );
            SecurityContextHolder.getContext().setAuthentication(userToken);
            chain.doFilter(request, response);
        }else{
            throw new TokenExpiredException("Token is not valid");
        }
    }

}
