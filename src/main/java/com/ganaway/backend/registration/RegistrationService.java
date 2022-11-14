package com.ganaway.backend.registration;

import com.ganaway.backend.apis.UserController;
import com.ganaway.backend.model.User;
import com.ganaway.backend.model.UserRole;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
@Service
@AllArgsConstructor
public class RegistrationService {

    private final UserController userController;
    private final EmailValidator emailValidator;


//    public String register(RegistrationRequest request) {
//        boolean isValidEmail = emailValidator.test(request.getEmail());
//        if(!isValidEmail){
//            throw new IllegalStateException("Email not valid");
//        }
//        return userController.signUpUser(new User(request.getUsername(), request.getPassword(), request.getEmail(), request.getUserRoles));
//    }
}
