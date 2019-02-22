package com.wenhao.springsecurity.springsecuritydemo.haddle;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;


import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {

    public void onAuthenticationFailure(HttpServletRequest req, HttpServletResponse res, AuthenticationException auth)
            throws IOException, ServletException {
        System.out.println("用户认证失败");
        res.sendRedirect("http://www.mayikt.com");
    }

}
