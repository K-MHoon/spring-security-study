package com.example.springsecuritystudy.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

import javax.servlet.http.HttpSession;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 인가
        http.authorizeRequests()
                .anyRequest().authenticated();

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
                    response.sendRedirect("/"); // root 페이지로 이동
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
    }
}
