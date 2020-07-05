package com.example.springsecurityjwt.filter;

import com.example.springsecurityjwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//This filter is used to pass through the /hello request with jwt

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

   @Autowired
   JwtUtil jwtUtil;

   @Autowired
   UserDetailsService userDetailsService;

   @Override
   protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain)
      throws ServletException, IOException {

      final String authorisationHeader = httpServletRequest.getHeader("Authorisation");
      String userName = null;
      String jwt = null;

      if (authorisationHeader != null && authorisationHeader.contains("Bearer ")) {
         jwt = authorisationHeader.substring(7);
         userName = jwtUtil.extractUsername(jwt);
      }

      if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
         UserDetails userDetails = this.userDetailsService.loadUserByUsername(userName);
         if (jwtUtil.validateToken(jwt, userDetails)) {
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
               userDetails, null, userDetails.getAuthorities());
            usernamePasswordAuthenticationToken
               .setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
         }
      }
      filterChain.doFilter(httpServletRequest, httpServletResponse);

   }
}
