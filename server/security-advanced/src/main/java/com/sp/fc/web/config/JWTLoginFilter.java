package com.sp.fc.web.config;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sp.fc.user.domain.SpUser;
import com.sp.fc.user.service.SpUserService;
import lombok.SneakyThrows;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//UsernamePassword필터의 기반으로 한다.
//UsernamePassword를 체크하고 인증이 성공하면 JWT 토큰을 넘겨준다
public class JWTLoginFilter extends UsernamePasswordAuthenticationFilter {

    // json 형식으로 들어오는 폼요청 정보를 읽어 dto로 변환하기 위해
    private ObjectMapper objectMapper = new ObjectMapper();
    private SpUserService userService;

    // AuthenticationManager 필요
    public JWTLoginFilter(AuthenticationManager authenticationManager, SpUserService userService) {
        super(authenticationManager);
        this.userService = userService;

        //longin post 요청을 처리
        setFilterProcessesUrl("/login");
    }

    // *********** 사용자가 로그인 할 경우 사용자 인증 처리 ***********
    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request,
            HttpServletResponse response) throws AuthenticationException
    {
        // 리퀘스트에서 InputStream 을 읽어 objectmapper를 통해 UserLoginForm으로 변환
        // TODO : 에러 처리 필요함
        UserLoginForm userLogin = objectMapper.readValue(
                request.getInputStream(),
                UserLoginForm.class
        );

        // refreshToken 이 없다면
        if(userLogin.getRefreshToken() == null) {

            // input 값으로 로그인을 할 수 있게 토큰 발행
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                    userLogin.getUsername(),
                    userLogin.getPassword(),
                    null // 인증되기 전이니
            );

            // 1, AuthenticationManager가 해당 토큰을 처리해줄수있는 provider(따로 설정안한 여기서는 DaoAuthenticationProvider)를 찾는다.
            // 2, provdier가 인증을 처리하여 인증이 성공한다면 토큰의 isAuthenticated 값을 true로 바꿔 리턴
            return getAuthenticationManager().authenticate(token);
        }else{
            // refreshToken 이미 있는 상태라면 유효성 검사하여 인증 토큰 발행
            VerifyResult verify = JWTUtil.verify(userLogin.getRefreshToken());
            if(verify.isSuccess()){
                SpUser user = (SpUser) userService.loadUserByUsername(verify.getUsername());
                return new UsernamePasswordAuthenticationToken(
                        user,
                        user.getAuthorities()
                );
            }else{
                throw new TokenExpiredException("refreshToken이 만료된 상태입니다.");
            }
        }
    }

    // 인증 성공시 자동으로 아래 메서드 호출
    @Override
    protected void successfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain,
            Authentication authResult
    ) throws IOException, ServletException{

        // 파라미터로 들어온 authResult가 위의 attemptAuthentication()에서 리턴한 Authentication 이다
        SpUser user = (SpUser) authResult.getPrincipal();

        // 사용자에게 토큰 전달
        response.setHeader(HttpHeaders.AUTHORIZATION,"Bearer "+JWTUtil.makeAuthToken(user));
//        response.setHeader("auth_token", JWTUtil.makeAuthToken(user));
//        response.setHeader("refresh_token", JWTUtil.makeRefreshToken(user));

        // response 헤더에 컨텐츠 타입을 json으로 지정
        response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

        // response outpuststream 에게 user를 써서 내려준다.
        response.getOutputStream().write(objectMapper.writeValueAsBytes(user));
    }
}
