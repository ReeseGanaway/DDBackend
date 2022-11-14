package com.ganaway.backend.apis;

import com.ganaway.backend.model.Character;
import com.ganaway.backend.repository.CharacterRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/characters")
public class CharacterController {

    @Autowired
    private CharacterRepository characterRepository;


    //get all characters

    @GetMapping("/get-all-characters")
    public List<Character> getAllCharacters(){
        return characterRepository.findAll();
    }
}
