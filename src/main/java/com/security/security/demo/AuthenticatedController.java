package com.security.security.demo;

import org.apache.coyote.Response;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/authenticated")
public class AuthenticatedController {

    @GetMapping
    public ResponseEntity<String> sayHello(){
        return ResponseEntity.ok("You are secure my friend");
    }
}
