package com.example.springJWT.controller;

import com.example.springJWT.dto.JoinDTO;
import com.example.springJWT.service.JoinService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JoinController {

    private final JoinService joinService;

    public JoinController(JoinService joinService) {
        this.joinService = joinService;
    }

    @PostMapping("/join")
    public String joinProc(JoinDTO joinDTO) {

        joinService.joinProcess(joinDTO);

        return "ok";
    }

}
