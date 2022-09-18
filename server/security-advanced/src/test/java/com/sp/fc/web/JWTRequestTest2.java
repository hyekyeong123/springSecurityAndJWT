package com.sp.fc.web;

import com.sp.fc.user.domain.SpUser;
import com.sp.fc.user.repository.SpUserRepository;
import com.sp.fc.user.service.SpUserService;
import com.sp.fc.web.config.UserLoginForm;
import com.sp.fc.web.test.WebIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class JWTRequestTest2 extends WebIntegrationTest {

    @Autowired private SpUserService spUserService;
    @Autowired private SpUserRepository spUserRepository;

    // 유저 등록
    @BeforeEach
    void before(){
        spUserRepository.deleteAll();
        SpUser spUser = spUserService.save(SpUser.builder()
            .email("user1")
            .password("1111")
            .enabled(true)
            .build());

        spUserService.addAuthority(spUser.getUserId(), "ROLE_USER");
    }

    @DisplayName("********** 1. hello 메시지를 받아온다... ********** ")
    @Test
    void test_1(){
        RestTemplate client = new RestTemplate();

        // ********** 1. 로그인하기 **********
        HttpEntity<UserLoginForm> body = new HttpEntity<>(
        UserLoginForm.builder()
                .username("user1")
                .password("1111")
                .build()
        );

        // ********** 2. 로그인 성공 **********
        ResponseEntity<SpUser> resp1= client.exchange(
            uri("/login")
            ,HttpMethod.POST
            ,body
            ,SpUser.class
        );
        System.out.println("[JHG] HttpHeaders.AUTHORIZATION : "+resp1.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0));
        // Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImV4cCI6MTY2MzUwNDMxMX0.Wik90ED2T_6ZSpZBj1FRUcgWvy3Wp8E3_JNQhJm57AQ

        System.out.println("[JHG] body : "+resp1.getBody());
        // SpUser(userId=2, email=user1, password=1111, authorities=[SpAuthority(userId=2, authority=ROLE_USER)], enabled=true)

        // ********** 3. 유저 정보를 받았으니 프론트엔드에 정보 전달 **********
        HttpHeaders header = new HttpHeaders();

        // header에 토큰 저장
        header.add(HttpHeaders.AUTHORIZATION,resp1.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0));
        body = new HttpEntity<>(null, header);
        ResponseEntity<String> resp2 = client.exchange(
                uri("/greeting"),
                HttpMethod.GET,
                body,
                String.class);

        assertEquals("hello", resp2.getBody());
    }
}
