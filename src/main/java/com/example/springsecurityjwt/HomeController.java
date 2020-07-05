package com.example.springsecurityjwt;

import com.example.springsecurityjwt.model.AuthenticationRequest;
import com.example.springsecurityjwt.model.AuthenticationResponse;
import com.example.springsecurityjwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

   @Autowired
   private AuthenticationManager authenticationManager;

   @Autowired
   private UserDetailsService userDetailsService;

   @Autowired
   private JwtUtil jwtUtil;

   @GetMapping("/hello")
   public String all() {
      return ("<H1> Welcome to Spring security JWT</H1>");
   }

   @PostMapping("/authenticate")
   public ResponseEntity createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
      try {
         authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUName(),
            authenticationRequest.getPwd()));
      } catch (BadCredentialsException e) {
         throw new Exception("Invalid user name/password");
      }

      final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUName());

      final String jwt = jwtUtil.generateToken(userDetails);

      return ResponseEntity.ok(new AuthenticationResponse(jwt));

   }
}
