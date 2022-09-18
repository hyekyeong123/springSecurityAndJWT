package com.sp.fc.web.config;

import com.sp.fc.user.domain.SpUser;
import com.sp.fc.user.service.SpUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class AdvancedSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private SpUserService userService;

    // TODO : 변경 필요
    @Bean
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    // 테스트용
    @Bean
    public void initDB(){
        userService.save(SpUser.builder()
        .email("user1")
        .password("1111")
        .enabled(true)
        .build());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // 로그인을 처리해주는 로그인 필터
        JWTLoginFilter loginFilter = new JWTLoginFilter(authenticationManager(), userService);

        // 로그인된 토큰을 매번 리퀘스트마다 검증해주는 필터
        JWTCheckFilter checkFilter = new JWTCheckFilter(authenticationManager(), userService);

        // 토큰을 사용할려면 csrf().disable()해야함
        http.csrf().disable()

            // 세션 사용 안함
            .sessionManagement(session->
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            .addFilterAt(loginFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterAt(checkFilter, BasicAuthenticationFilter.class)
            ;

    }
}
