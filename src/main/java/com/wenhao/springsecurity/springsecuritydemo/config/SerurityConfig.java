package com.wenhao.springsecurity.springsecuritydemo.config;

import com.wenhao.springsecurity.springsecuritydemo.enity.Permission;
import com.wenhao.springsecurity.springsecuritydemo.haddle.MyAuthenticationFailureHandler;
import com.wenhao.springsecurity.springsecuritydemo.haddle.MyAuthenticationSuccessHandler;
import com.wenhao.springsecurity.springsecuritydemo.mapper.PermissionMapper;
import com.wenhao.springsecurity.springsecuritydemo.security.MyUserDetailsService;
import com.wenhao.springsecurity.springsecuritydemo.until.MD5Util;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@EnableWebSecurity
public class SerurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyAuthenticationFailureHandler failureHandler;

    @Autowired
    private MyAuthenticationSuccessHandler successHandler;

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Autowired
    private PermissionMapper permissionMapper;

    //配置认证用户信息和权限
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //auth.inMemoryAuthentication().withUser("admin").password("123456").authorities("showOrder", "addOrder", "updateOrder", "deleteOrder");
        //auth.inMemoryAuthentication().withUser("admin1").password("123456").authorities("showOrder", "addOrder");
        auth.userDetailsService(userDetailsService).passwordEncoder(new PasswordEncoder() {
            @Override
            public String encode(CharSequence rawPassword) {
                return MD5Util.encode((String) rawPassword);
            }

            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                return MD5Util.encode((String) rawPassword).equals(encodedPassword);
            }
        });
    }

    //配置拦截请求资源
    protected void configure(HttpSecurity http) throws Exception {
        /*http.authorizeRequests()
                .antMatchers("/showOrder").hasAuthority("showOrder")
                .antMatchers("/addOrder").hasAuthority("addOrder")
                .antMatchers("/updateOrder").hasAuthority("updateOrder")
                .antMatchers("/deleteOrder").hasAuthority("deleteOrder")
                .antMatchers("/login").permitAll()
                .antMatchers("/**").fullyAuthenticated().and().formLogin().loginPage("/login").successHandler(successHandler)
                //.failureHandler(failureHandler)
                .and()
                .csrf().disable();*/
        ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry authorizeRequests = http.authorizeRequests();
        // 查询数据库获取权限列表
        List<Permission> listPermission = permissionMapper.findAllPermission();
        for (Permission permission : listPermission) {
            authorizeRequests.antMatchers(permission.getUrl()).hasAuthority(permission.getPermTag());
        }
        authorizeRequests.antMatchers("/login")
                .permitAll()
                .antMatchers("/**")
                .fullyAuthenticated().and().formLogin()
                .loginPage("/login").successHandler(successHandler)
                .failureHandler(failureHandler)
                .and().csrf()
                .disable();
    }

    @Bean
    public static NoOpPasswordEncoder passwordEncoder() {
        return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    }

}
