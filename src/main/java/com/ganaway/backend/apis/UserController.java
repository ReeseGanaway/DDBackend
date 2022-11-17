package com.ganaway.backend.apis;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ganaway.backend.model.User;
import com.ganaway.backend.model.UserRole;
import com.ganaway.backend.service.UserService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1")
public class UserController{

    private final UserService userService;

    //get all characters

    @GetMapping("/get-all-users")
    public ResponseEntity<List<User>>getUsers(){
        return ResponseEntity.ok().body(userService.getUsers());
    }

    @GetMapping("/get-user")
//    public ResponseEntity<User>getUser(@RequestBody String username){
//      User userDetails = (User) SecurityContextHolder.getContext().getAuthentication()
//                .getPrincipal();
//        log.info("currentUser : {}", username );
//        String currentUser = userDetails.getUsername();
//
//        if(currentUser.equals(username)){
//        return ResponseEntity.ok().body(userService.getUser(username));
//    }
//        else{
//            throw new RuntimeException("Not allowed");
//        }
//    }
    public void getUser(HttpServletRequest request, HttpServletResponse response, @RequestBody User username) throws IOException{
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                String access_token = authorizationHeader.substring("Bearer ".length());
                //        "secret" need to be encrypted later
                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(access_token);
                String remoteUser = decodedJWT.getSubject();
                log.info("remote user : {} , username : {} ",remoteUser, username);
                if(remoteUser.equals(username.getUsername())){
                User user = userService.getUser(username.getUsername());
                Map<String, String> userInfo = new HashMap<>();
                userInfo.put("username", user.getUsername());
                userInfo.put("email", user.getEmail());
                userInfo.put("roles", user.getUserRoles().toString());
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), userInfo);}
                else{
                    throw new RuntimeException("You don't have access to this user's data.");
                }
            } catch (Exception exception) {
                response.setHeader("error", exception.getMessage());
                response.setStatus(FORBIDDEN.value());
                //response.sendError(FORBIDDEN.value());
                Map<String, String> error = new HashMap<>();
                error.put("error_message", exception.getMessage());
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);
            }
        }
    }

    @PostMapping("/user/save")
    public ResponseEntity<User>saveUser(@RequestBody User user){
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/v1/users/save-user").toUriString());
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping("/signup")
    public ResponseEntity<User>signup(@RequestBody User user){
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/v1/users/save-user").toUriString());
        return ResponseEntity.created(uri).body(userService.signup(user));
    }

    @PostMapping("/create-role")
    public ResponseEntity<UserRole>saveRole(@RequestBody UserRole role){
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/v1/users/create-role").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping("/give-role")
    public ResponseEntity<UserRole>giveRoleToUser(@RequestBody RoleToUserForm form){
        userService.setUserRole(form.getUsername(), form.getRoleName());
        return ResponseEntity.ok().build();
    }

    @GetMapping("/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        log.info("HERE");
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        //want to create a utility class for the creation of tokens
        if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
            try{
                String refresh_token = authorizationHeader.substring("Bearer ".length());
                //        "secret" need to be encrypted later
                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(refresh_token);
                String username = decodedJWT.getSubject();
                User user = userService.getUser(username);
                String access_token = JWT.create()
                        .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 60*60*1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", user.getUserRoles().stream().map(UserRole::getName).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String, String> tokens = new HashMap<>();
                tokens.put("access_token", access_token);
                tokens.put("refresh_token", refresh_token);
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);
            }catch(Exception exception){
                response.setHeader("error", exception.getMessage());
                response.setStatus(FORBIDDEN.value());
                //response.sendError(FORBIDDEN.value());
                Map<String, String> error = new HashMap<>();
                error.put("error_message", exception.getMessage());
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);
            }

        }
        else{
            //add an error message here
            throw new RuntimeException("Refresh token is missing");
        }
    }

}

@Data
class RoleToUserForm{
    private String username;
    private String roleName;
}
