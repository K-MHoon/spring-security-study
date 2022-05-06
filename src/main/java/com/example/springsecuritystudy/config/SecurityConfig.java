package com.example.springsecuritystudy.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 임시 사용자 목록 생성
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 로그인 인증
        http.formLogin()
//                .loginPage("/loginPage") // 커스텀한 로그인 페이지 설정 가능 (로그인 해야될 경우 보이는 화면)
                .defaultSuccessUrl("/")
                .failureUrl("/login")
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc")
                .successHandler((request, response, authentication) -> { // 로그인 성공했을 경우
                    System.out.println("authentication" + authentication.getName());
                    // 사용자가 원래 가고자 했던 정보를 가지고 있음.
                    HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
                    SavedRequest savedRequest = requestCache.getRequest(request, response);
                    String redirectUrl = savedRequest.getRedirectUrl();
                    response.sendRedirect(redirectUrl);
                })
                .failureHandler((request, response, exception) -> { // 로그인 실패했을 경우
                    System.out.println("exception" + exception.getMessage());
                    response.sendRedirect("/login"); // 로그인 페이지로 이동
                })
                .permitAll();

        // 로그아웃
        http.logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .addLogoutHandler((request, response, authentication) -> {
                    HttpSession session = request.getSession();
                    session.invalidate();
                })
                .logoutSuccessHandler((request, response, authentication) -> {
                    response.sendRedirect("/login");
                })
                .deleteCookies("remember-me");

        // remember Me
        http.rememberMe()
                .rememberMeParameter("remember")
                .tokenValiditySeconds(3600)
                .userDetailsService(userDetailsService);

        http.sessionManagement()
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false) // true 면 다른 사용자 로그인 불가능, false 면 다른 사용자가 로그인하고, 이전 사용자 세션이 제거
                .and()
                .sessionFixation() // 세션 고정 보호
                .changeSessionId(); // 로그인할 때마다 새로운 세션을 발급한다.

        // 권한 분리
        http.authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();

        // 인증, 인가 예외처리
        http
                .exceptionHandling()
//                .authenticationEntryPoint((request, response, authException) ->
//                        response.sendRedirect("/login"))
                .accessDeniedHandler((request, response, accessDeniedException) ->
                        response.sendRedirect("/denied"));
    }
}
