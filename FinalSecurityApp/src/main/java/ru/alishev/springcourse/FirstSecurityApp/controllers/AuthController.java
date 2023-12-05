package ru.alishev.springcourse.FirstSecurityApp.controllers;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import ru.alishev.springcourse.FirstSecurityApp.dto.AuthenticationDto;
import ru.alishev.springcourse.FirstSecurityApp.dto.PersonDto;
import ru.alishev.springcourse.FirstSecurityApp.models.Person;
import ru.alishev.springcourse.FirstSecurityApp.security.JwtUtil;
import ru.alishev.springcourse.FirstSecurityApp.services.RegistrationService;
import ru.alishev.springcourse.FirstSecurityApp.util.PersonValidator;

import javax.validation.Valid;
import java.util.Map;

/**
 * @author Neil Alishev
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final RegistrationService registrationService;
    private final PersonValidator personValidator;
    private final JwtUtil jwtUtil;
    private final ModelMapper modelMapper;
    private final AuthenticationManager authenticationManager;

    @Autowired
    public AuthController(RegistrationService registrationService, PersonValidator personValidator, JwtUtil jwtUtil, ModelMapper modelMapper, AuthenticationManager authenticationManager) {
        this.registrationService = registrationService;
        this.personValidator = personValidator;
        this.jwtUtil = jwtUtil;
        this.modelMapper = modelMapper;
        this.authenticationManager = authenticationManager;
    }

//    @GetMapping("/login")
//    public String loginPage() {
//        return "auth/login";
//    }
//
//    @GetMapping("/registration")
//    public String registrationPage(@ModelAttribute("person") Person person) {
//        return "auth/registration";
//    }

    @PostMapping("/registration")
    public Map<String, String> performRegistration(@RequestBody @Valid PersonDto personDto,
                                                   BindingResult bindingResult) {
        Person person = convertToPerson(personDto);

        personValidator.validate(person, bindingResult);

        if (bindingResult.hasErrors())
            return Map.of("message", "Ошибка!");

        registrationService.register(person);

        String token = jwtUtil.generateToken(person.getUsername());
        return Map.of("jwt-token", token);
    }

    @PostMapping("/login")
    public Map<String, String> performLogin(@RequestBody AuthenticationDto authenticationDto) {
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                authenticationDto.getUsername(),
                authenticationDto.getPassword());
        try {
            authenticationManager.authenticate(authToken);
        } catch (BadCredentialsException e) {
            return Map.of("message", "Incorrect credentials!");
        }
        String token = jwtUtil.generateToken(authenticationDto.getUsername());

        return Map.of("jwt-token", token);

    }

    public Person convertToPerson(PersonDto personDto) {
        return modelMapper.map(personDto, Person.class);
    }

}
