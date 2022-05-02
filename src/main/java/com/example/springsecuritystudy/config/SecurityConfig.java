package com.example.springsecuritystudy.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 인가
        http.authorizeRequests()
                .anyRequest().authenticated();

        // 인증
        http.formLogin()
                .loginPage("/loginPage") // 커스텀한 로그인 페이지 설정 가능 (로그인 해야될 경우 보이는 화면)
                .defaultSuccessUrl("/")
                .failureUrl("/login")
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc")
                .successHandler((request, response, authentication) -> { // 로그인 성공했을 경우
                    System.out.println("authentication" + authentication.getName());
                    response.sendRedirect("/"); // root 페이지로 이동
                })
                .failureHandler((request, response, exception) -> { // 로그인 실패했을 경우
                    System.out.println("exception" + exception.getMessage());
                    response.sendRedirect("/login"); // 로그인 페이지로 이동
                })
                .permitAll();
    }
}
