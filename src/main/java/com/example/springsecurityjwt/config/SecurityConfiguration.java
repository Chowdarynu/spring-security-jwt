package com.example.springsecurityjwt.config;


import com.example.springsecurityjwt.filter.JwtRequestFilter;
import com.example.springsecurityjwt.service.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

   @Autowired
   MyUserDetailsService myUserDetailsService;

   @Autowired
   private JwtRequestFilter jwtRequestFilter;


   //For jdbc authentication
   @Override
   protected void configure(AuthenticationManagerBuilder auth) throws Exception {
      auth.userDetailsService(myUserDetailsService);

   }

   @Override
   @Bean
   protected AuthenticationManager authenticationManager() throws Exception {
      return super.authenticationManager();
   }

   //For authorisations
   @Override
   protected void configure(HttpSecurity http) throws Exception {
      http.csrf().disable()
         .authorizeRequests().antMatchers("/authenticate").permitAll()//to disable for this endpoint
         .anyRequest().authenticated()
         .and().exceptionHandling().and().sessionManagement()
         .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
      http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
   }

   //This is for password encoding
   @Bean
   public PasswordEncoder passwordEncoder() {
      return NoOpPasswordEncoder.getInstance();
   }


}
