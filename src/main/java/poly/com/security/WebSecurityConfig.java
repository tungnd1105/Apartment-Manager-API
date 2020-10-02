package poly.com.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import poly.com.security.jwt.JwtAuthenticationFilter;
import poly.com.security.services.UserService;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    /* ------------------------------------ WebSecurityConfig -------------------------------- */

    @Autowired
    UserService userService;

    @Bean /*---------------- provider JwtAuthenticationFilter --------------- */
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }

    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    /* ----------------------------------------------------------------------- */

    @Override /* ------------cung cap account cho spring security  -----------------*/
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService).passwordEncoder(passwordEncoder());
    }


    @Bean /*  ------------------ config CorsOrigin ---------------------- */
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowCredentials(true);
        configuration.addAllowedOrigin("Localhost:5000"); /* chi cho phep domain nay gui request*/
        configuration.addAllowedHeader("*");
        /* cho phep cac request method gui request len server */
        configuration.addAllowedMethod("GET");
        configuration.addAllowedMethod("POST");
        configuration.addAllowedMethod("PUT");
        configuration.addAllowedMethod("DELETE");
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Override  /* --------------- configure HttpSecurity --------------- */
    protected void configure(HttpSecurity http) throws Exception {
        http.rememberMe().key("uniqueAndSecret").tokenValiditySeconds(86400);
        http.csrf().disable();
        http.headers().cacheControl();    // khong cho browser tu dong cache
        http.cors();
        http
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/api/authencation/account/login").permitAll()
                // <-------------- Role User ------------->
                .antMatchers("/api/price/**",
                                        "/api/account/*",
                                        "/api/apartment-index/**",
                                        "/api/vehicle/**",
                                        "/api/email/*").hasAnyAuthority("ROLE_USER")
                // <-------------- Role Admin ------------->
                .antMatchers("/api/employee/**",
                                        "/api/account/*",
                                        "/api/email/*",
                                        "/api/apartment/**",
                                        "/api/notification/**",
                                        "/api/own-apartment/**",
                                        "/api/resident/**",
                                        "/api/regulation/**").hasAnyAuthority("ROLE_ADMIN")
                .anyRequest().authenticated() // tat cac request khac  phai duoc xac thuc
                .and().addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

    }


}